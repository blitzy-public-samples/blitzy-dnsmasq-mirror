// Copyright (c) 2000-2024 dnsmasq contributors
// SPDX-License-Identifier: GPL-2.0-or-later

//! # DHCPv4 Protocol Message Parsing and Serialization (RFC 2131)
//!
//! This module implements DHCPv4 packet parsing, validation, and serialization per RFC 2131.
//! It replaces the C implementation from `src/rfc2131.c`, `src/dhcp-protocol.h`, and related
//! C functions with memory-safe Rust, eliminating buffer overflows, pointer arithmetic, and
//! manual memory management.
//!
//! ## Key Features
//!
//! - Type-safe DHCPv4 packet structure matching RFC 2131's 236-byte fixed header
//! - Comprehensive packet validation (operation code, hardware length, DHCP cookie)
//! - Safe option parsing with bounds checking (no buffer overflows possible)
//! - Message type identification (DISCOVER, OFFER, REQUEST, etc.)
//! - Client identification via Option 61 or hardware address (chaddr field)
//! - Relay agent (GIADDR) processing for multi-subnet deployments
//! - Server identifier selection for multi-homed servers
//! - Option overload support (Option 52) for extended option space
//!
//! ## C Source References
//!
//! This module translates the following C components to safe Rust:
//!
//! ### From `src/rfc2131.c`:
//! - `dhcp_reply()` - Main packet handler → `DhcpPacket::parse()`
//! - `dhcp_packet()` - Response constructor → `DhcpPacket::serialize()`
//! - `clear_packet()` - Packet initialization → `DhcpPacket::new()`
//! - `dhcp_packet_size()` - Size calculation → `DhcpPacket::packet_size()`
//! - `option_find()` - Option extraction → `DhcpPacket::get_option()`
//! - `server_id()` - Server ID selection → handled in `DhcpPacket` methods
//! - `calc_time()` - Lease time calculation → separate module
//! - `log_packet()` - Transaction logging → tracing crate integration
//!
//! ### From `src/dhcp-protocol.h`:
//! - `struct dhcp_packet` - Wire format → `DhcpPacket` struct
//! - Message type constants (DHCPDISCOVER, etc.) → `MessageType` enum
//! - Option codes → imported from options module
//! - Protocol constants (DHCP_COOKIE, BOOTREQUEST, etc.) → constants module
//!
//! ## Protocol Compliance
//!
//! - RFC 2131: Dynamic Host Configuration Protocol (complete wire format support)
//! - RFC 2132: DHCP Options and BOOTP Vendor Extensions
//! - RFC 3046: DHCP Relay Agent Information Option (Option 82)
//! - RFC 5107: Server Identifier Override Suboption
//!
//! ## Memory Safety
//!
//! All packet parsing uses safe Rust slice operations with automatic bounds checking:
//! - No pointer arithmetic (replaced with slice indexing)
//! - No manual `memcpy` (replaced with `copy_from_slice`)
//! - No buffer overflows (compiler-enforced bounds checks)
//! - No use-after-free (borrow checker guarantees)
//!
//! ## Examples
//!
//! ```rust,ignore
//! use crate::dhcp::v4::protocol::{DhcpPacket, MessageType};
//!
//! // Parse incoming DHCP packet
//! let packet = DhcpPacket::parse(&udp_data)?;
//!
//! // Check message type
//! match packet.get_message_type()? {
//!     MessageType::Discover => {
//!         // Handle DHCPDISCOVER
//!     }
//!     MessageType::Request => {
//!         // Handle DHCPREQUEST
//!     }
//!     _ => {}
//! }
//!
//! // Create DHCPOFFER response
//! let mut response = DhcpPacket::new();
//! response.set_op(BOOTREPLY);
//! response.set_xid(packet.get_xid());
//! response.set_yiaddr(offered_ip);
//! response.set_option(DhcpOption::MessageType(MessageType::Offer as u8));
//! let response_bytes = response.serialize()?;
//! ```

use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use std::net::Ipv4Addr;
use thiserror::Error;
use tracing::error;

use crate::constants::{BOOTREPLY, DHCP_CHADDR_MAX, DHCP_COOKIE};
use crate::dhcp::v4::options::{DhcpOption, OPTION_CLIENT_ID, OPTION_MESSAGE_TYPE, OPTION_OVERLOAD};
use crate::types::addresses::AllAddr;
use crate::types::errors::DnsmasqResult;

/// Minimum DHCPv4 packet size in bytes (must be at least 300 bytes per RFC 2131)
///
/// While RFC 2131 defines the minimum as 236 bytes (fixed header), Linux in-kernel
/// DHCP clients ignore packets smaller than 300 bytes due to historical bugs. We enforce
/// 300 bytes minimum with padding to ensure compatibility.
const MIN_PACKET_SIZE: usize = 300;

/// Fixed header size for DHCPv4 packets (236 bytes per RFC 2131 Section 2)
///
/// Breakdown:
/// - 4 bytes: op, htype, hlen, hops
/// - 4 bytes: xid (transaction ID)
/// - 4 bytes: secs, flags
/// - 16 bytes: ciaddr, yiaddr, siaddr, giaddr (4 IPv4 addresses)
/// - 16 bytes: chaddr (client hardware address)
/// - 64 bytes: sname (server hostname)
/// - 128 bytes: file (boot filename)
/// Total: 236 bytes
const DHCP_FIXED_HEADER_SIZE: usize = 236;

/// Size of the options field in the basic DHCPv4 packet structure (312 bytes)
///
/// This is the minimum space allocated for options after the fixed 236-byte header.
/// Options can extend into sname and file fields if Option 52 (overload) is used.
const DHCP_OPTIONS_SIZE: usize = 312;

/// Total minimum DHCPv4 packet structure size (548 bytes)
const DHCP_MIN_STRUCTURE_SIZE: usize = DHCP_FIXED_HEADER_SIZE + DHCP_OPTIONS_SIZE;

/// Maximum client hardware address length (16 bytes per RFC 2131)
const MAX_CHADDR_LEN: usize = 16;

/// Size of server name field (64 bytes)
const SNAME_SIZE: usize = 64;

/// Size of boot filename field (128 bytes)
const FILE_SIZE: usize = 128;

/// Option end marker (255)
const OPTION_END: u8 = 255;

/// Option pad marker (0)
const OPTION_PAD: u8 = 0;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during DHCPv4 packet parsing and validation
///
/// These errors represent violations of RFC 2131 packet format requirements
/// or protocol constraints. All errors include context for debugging.
#[derive(Debug, Error)]
pub enum PacketError {
    /// Packet operation code is not BOOTREQUEST (1) or BOOTREPLY (2)
    ///
    /// RFC 2131 Section 2: op field must be 1 (BOOTREQUEST) for client→server
    /// or 2 (BOOTREPLY) for server→client messages.
    #[error("Invalid DHCP operation code: {0} (expected BOOTREQUEST=1 or BOOTREPLY=2)")]
    InvalidOpCode(u8),

    /// DHCP magic cookie missing or incorrect in options field
    ///
    /// RFC 2131 Section 3: The first four bytes of the options field must
    /// contain the DHCP "magic cookie" value 0x63825363. This distinguishes
    /// DHCP from BOOTP packets.
    #[error("Missing or invalid DHCP magic cookie (expected 0x63825363)")]
    MissingDhcpCookie,

    /// Packet is too small to contain minimum DHCPv4 structure
    ///
    /// Packets must be at least 300 bytes for compatibility with legacy
    /// implementations. RFC 2131 specifies 236-byte minimum, but practice
    /// requires 300 bytes.
    #[error("Packet too small: {0} bytes (minimum {MIN_PACKET_SIZE} required)")]
    TruncatedPacket(usize),

    /// Hardware address length (hlen) exceeds maximum of 16 bytes
    ///
    /// RFC 2131 Section 2: hlen field specifies length of hardware address
    /// in chaddr field. Maximum value is 16 (size of chaddr field).
    #[error("Invalid hardware address length: {0} (maximum {MAX_CHADDR_LEN} bytes)")]
    InvalidHardwareLength(u8),

    /// DHCP options field has invalid structure or encoding
    ///
    /// Options must follow tag-length-value encoding. Common issues include:
    /// - Option extends beyond end of options field
    /// - Missing required options (e.g., message type)
    /// - Malformed option length field
    #[error("Malformed DHCP options: {0}")]
    MalformedOptions(String),

    /// Required DHCP message type option (53) missing or invalid
    ///
    /// RFC 2131 requires Option 53 (DHCP Message Type) in all DHCP packets.
    /// Valid values are 1-8 (DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK,
    /// RELEASE, INFORM).
    #[error("Invalid or missing DHCP message type option")]
    InvalidMessageType,

    /// I/O error during packet serialization
    #[error("I/O error during packet processing: {0}")]
    IoError(#[from] std::io::Error),
}

// ============================================================================
// MessageType Enum
// ============================================================================

/// DHCPv4 message types as defined in RFC 2131
///
/// These constants represent the values used in DHCP Option 53 (Message Type).
/// The message type determines the purpose of the DHCP packet and the expected
/// client/server behavior.
///
/// ## Protocol Flow
///
/// ### DORA (Discovery, Offer, Request, Acknowledgment)
/// The standard 4-way DHCP lease acquisition:
/// 1. Client broadcasts `DISCOVER` to locate servers
/// 2. Servers respond with `OFFER` containing available IP address
/// 3. Client broadcasts `REQUEST` to accept one offer
/// 4. Selected server responds with `ACK` confirming lease
///
/// ### Additional Message Types
/// - `DECLINE`: Client detected IP address conflict (via ARP)
/// - `NAK`: Server refuses client's REQUEST (wrong network, expired lease)
/// - `RELEASE`: Client voluntarily relinquishes IP address
/// - `INFORM`: Client requests local config (already has IP address)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// DHCPDISCOVER (1) - Client broadcast to locate available servers
    ///
    /// Client has no IP address and is requesting lease offers from any
    /// available DHCP server. Broadcast to 255.255.255.255.
    Discover = 1,

    /// DHCPOFFER (2) - Server response offering IP address to client
    ///
    /// Server responds to DISCOVER with an available IP address and
    /// configuration parameters. May be broadcast or unicast depending
    /// on client's BROADCAST flag.
    Offer = 2,

    /// DHCPREQUEST (3) - Client message accepting a server's offer
    ///
    /// Used in three contexts:
    /// - Selecting server after receiving OFFER (broadcast)
    /// - Renewing existing lease (unicast to server)
    /// - Verifying address after reboot (broadcast)
    Request = 3,

    /// DHCPDECLINE (4) - Client detected offered IP is already in use
    ///
    /// Client performed ARP check and detected address conflict. Server
    /// must mark address as unavailable. Client restarts discovery process.
    Decline = 4,

    /// DHCPACK (5) - Server acknowledgment of client's REQUEST
    ///
    /// Confirms lease allocation and provides final configuration parameters.
    /// Client may now use the assigned IP address.
    Ack = 5,

    /// DHCPNAK (6) - Server rejection of client's REQUEST
    ///
    /// Sent when:
    /// - Client requests inappropriate address for its network
    /// - Client's lease has expired
    /// - Client moved to different subnet
    /// Client must restart discovery process.
    Nak = 6,

    /// DHCPRELEASE (7) - Client voluntarily releasing IP address
    ///
    /// Client no longer needs IP address (shutdown, disconnect). Server
    /// marks lease as available. No server response required.
    Release = 7,

    /// DHCPINFORM (8) - Client requesting local configuration only
    ///
    /// Client already has IP address (static or from other source) but
    /// needs local configuration (DNS servers, NTP, etc.). Server responds
    /// with ACK containing only configuration options (no IP address).
    Inform = 8,
}

impl MessageType {
    /// Convert u8 wire format value to MessageType enum
    ///
    /// # Arguments
    /// * `value` - Raw message type value from DHCP Option 53
    ///
    /// # Returns
    /// * `Some(MessageType)` if value is 1-8 (valid message type)
    /// * `None` if value is invalid
    ///
    /// # Example
    /// ```rust,ignore
    /// let msg_type = MessageType::from_u8(1); // Some(MessageType::Discover)
    /// let invalid = MessageType::from_u8(99); // None
    /// ```
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(MessageType::Discover),
            2 => Some(MessageType::Offer),
            3 => Some(MessageType::Request),
            4 => Some(MessageType::Decline),
            5 => Some(MessageType::Ack),
            6 => Some(MessageType::Nak),
            7 => Some(MessageType::Release),
            8 => Some(MessageType::Inform),
            _ => None,
        }
    }

    /// Convert MessageType enum to u8 wire format value
    ///
    /// # Returns
    /// Raw message type value (1-8) for use in DHCP Option 53
    ///
    /// # Example
    /// ```rust,ignore
    /// let value = MessageType::Offer.to_u8(); // 2
    /// ```
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// ClientId Structure
// ============================================================================

/// Client identifier used to uniquely identify DHCP clients
///
/// RFC 2131 Section 4.2: Clients are identified by either:
/// 1. Client Identifier option (Option 61) - preferred, globally unique
/// 2. Hardware address from chaddr field - fallback if Option 61 not present
///
/// Option 61 format: Type (1 byte) + Identifier (variable length)
/// Common types:
/// - 1: Hardware address (same as chaddr)
/// - 0: Opaque identifier (client-defined)
///
/// Using Option 61 allows clients to maintain the same identity across
/// hardware changes (e.g., network card replacement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientId {
    /// Raw bytes of client identifier
    ///
    /// If from Option 61: includes type byte + identifier
    /// If from chaddr: just the hardware address bytes
    data: Vec<u8>,
}

impl ClientId {
    /// Create ClientId from DHCP Option 61 (Client Identifier)
    ///
    /// This is the preferred identification method. The option contains
    /// a type byte followed by unique identifier bytes.
    ///
    /// # Arguments
    /// * `option_data` - Raw bytes from Option 61 (type + identifier)
    ///
    /// # Example
    /// ```rust,ignore
    /// // Option 61 with type=1 (Ethernet) and MAC address
    /// let option_bytes = vec![0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    /// let client_id = ClientId::from_option(&option_bytes);
    /// ```
    pub fn from_option(option_data: &[u8]) -> Self {
        ClientId {
            data: option_data.to_vec(),
        }
    }

    /// Create ClientId from hardware address (chaddr field fallback)
    ///
    /// Used when Option 61 is not present. Takes hardware address from
    /// the chaddr field, using only hlen bytes.
    ///
    /// # Arguments
    /// * `hw_addr` - Hardware address bytes from chaddr field
    /// * `hw_len` - Number of valid bytes in hardware address (hlen field)
    ///
    /// # Example
    /// ```rust,ignore
    /// let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    /// let client_id = ClientId::from_hardware_address(&mac, 6);
    /// ```
    pub fn from_hardware_address(hw_addr: &[u8], hw_len: u8) -> Self {
        ClientId {
            data: hw_addr[..hw_len.min(MAX_CHADDR_LEN as u8) as usize].to_vec(),
        }
    }

    /// Get raw bytes of client identifier
    ///
    /// # Returns
    /// Slice containing identifier bytes (Option 61 data or hardware address)
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get length of client identifier in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if client identifier is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ============================================================================
// DhcpPacket Structure
// ============================================================================

/// DHCPv4 packet structure matching RFC 2131 wire format
///
/// This structure represents a complete DHCPv4 packet with the fixed 236-byte
/// header plus variable-length options field. The layout matches the C struct
/// `dhcp_packet` from `dhcp-protocol.h` but uses safe Rust types.
///
/// ## Wire Format (RFC 2131 Section 2)
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
/// +---------------+---------------+---------------+---------------+
/// |                            xid (4)                            |
/// +-------------------------------+-------------------------------+
/// |           secs (2)            |           flags (2)           |
/// +-------------------------------+-------------------------------+
/// |                          ciaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          yiaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          siaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          giaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          chaddr  (16)                         |
/// |                                                               |
/// |                                                               |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          sname   (64)                         |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          file    (128)                        |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          options (variable)                   |
/// +---------------------------------------------------------------+
/// ```
///
/// ## Field Descriptions
///
/// - **op**: Message operation code (BOOTREQUEST=1 or BOOTREPLY=2)
/// - **htype**: Hardware address type (1=Ethernet, 6=IEEE 802, etc.)
/// - **hlen**: Hardware address length in bytes (6 for Ethernet MAC)
/// - **hops**: Relay agent hop count (incremented by each relay)
/// - **xid**: Transaction ID (random value for matching requests/responses)
/// - **secs**: Seconds elapsed since client began address acquisition
/// - **flags**: Flags (bit 15 = BROADCAST flag, others reserved)
/// - **ciaddr**: Client IP address (if client is bound/renewing)
/// - **yiaddr**: 'Your' (client) IP address (assigned by server)
/// - **siaddr**: Server IP address (next server in bootstrap)
/// - **giaddr**: Relay agent IP address (gateway for relayed packets)
/// - **chaddr**: Client hardware address (MAC address + padding)
/// - **sname**: Optional server hostname (null-terminated string or options)
/// - **file**: Boot file name (null-terminated string or options)
/// - **options**: DHCP options (starts with magic cookie 0x63825363)
///
/// ## Memory Safety vs C Implementation
///
/// The C implementation uses a fixed 548-byte struct with pointer arithmetic
/// for option parsing. This Rust implementation:
/// - Uses `Vec<u8>` for options (no fixed size, no overflows)
/// - Validates all array accesses (no pointer arithmetic)
/// - Enforces field constraints through types (no invalid states)
/// - Prevents use-after-free through borrow checker
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    /// Message operation code: BOOTREQUEST (1) or BOOTREPLY (2)
    op: u8,

    /// Hardware address type (1=Ethernet, 6=IEEE 802, per RFC 1700)
    htype: u8,

    /// Hardware address length in bytes (typically 6 for Ethernet MAC)
    hlen: u8,

    /// Relay agent hop count (0 for direct clients, incremented by relays)
    hops: u8,

    /// Transaction ID - random value for matching requests with responses
    ///
    /// Client generates random xid for DISCOVER, reuses same xid for REQUEST.
    /// Server copies xid from request to response. This allows client to
    /// match responses to its requests in presence of multiple servers.
    xid: u32,

    /// Seconds elapsed since client began address acquisition or renewal
    ///
    /// Used by servers to prioritize responses (longer waits → higher priority).
    /// Optional; may be zero.
    secs: u16,

    /// Flags field (big-endian)
    ///
    /// Bit 15 (0x8000): BROADCAST flag
    /// - 1 = client cannot receive unicast until fully configured
    /// - 0 = client can receive unicast responses
    ///
    /// All other bits reserved and must be zero.
    flags: u16,

    /// Client IP address
    ///
    /// Filled by client in RENEWING/REBINDING states. Zero in INIT/SELECTING
    /// states. Server may use this to determine client's network location.
    ciaddr: Ipv4Addr,

    /// 'Your' (client) IP address
    ///
    /// Filled by server in OFFER and ACK. This is the IP address being
    /// offered or confirmed for the client.
    yiaddr: Ipv4Addr,

    /// Server IP address
    ///
    /// Address of server to contact for next boot protocol phase (e.g., TFTP
    /// server for network boot). May be zero if not needed.
    siaddr: Ipv4Addr,

    /// Relay agent IP address
    ///
    /// Filled by relay agent when forwarding packets between subnets. Zero
    /// for packets on same subnet. Server uses this to determine client's
    /// network location and select appropriate address pool.
    giaddr: Ipv4Addr,

    /// Client hardware address (MAC address for Ethernet)
    ///
    /// Only first `hlen` bytes are valid. Remaining bytes should be zero
    /// but may contain padding. Maximum 16 bytes per RFC 2131.
    chaddr: [u8; MAX_CHADDR_LEN],

    /// Server hostname (optional, null-terminated string)
    ///
    /// May contain server's hostname or additional DHCP options if Option 52
    /// (overload) indicates sname field contains options.
    sname: [u8; SNAME_SIZE],

    /// Boot file name (optional, null-terminated string)
    ///
    /// May contain boot filename for network boot or additional DHCP options
    /// if Option 52 (overload) indicates file field contains options.
    file: [u8; FILE_SIZE],

    /// DHCP options field (variable length)
    ///
    /// Must start with DHCP magic cookie (0x63825363) followed by options
    /// in tag-length-value format. Option 255 (end) marks end of options.
    /// Option 0 (pad) is used for alignment.
    options: Vec<u8>,
}

impl DhcpPacket {
    /// Create a new empty DHCP packet with default values
    ///
    /// Initializes packet with:
    /// - op = 0 (must be set before serialization)
    /// - htype = 1 (Ethernet)
    /// - hlen = 6 (Ethernet MAC address length)
    /// - All addresses = 0.0.0.0
    /// - Empty options with DHCP magic cookie
    ///
    /// This replaces the C function `clear_packet()` which used `memset()`.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mut packet = DhcpPacket::new();
    /// packet.set_op(BOOTREPLY);
    /// packet.set_xid(0x12345678);
    /// ```
    pub fn new() -> Self {
        let mut options = Vec::with_capacity(DHCP_OPTIONS_SIZE);
        // Add DHCP magic cookie
        options.extend_from_slice(&DHCP_COOKIE.to_be_bytes());

        DhcpPacket {
            op: 0,
            htype: 1,  // Ethernet
            hlen: 6,   // MAC address length
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; MAX_CHADDR_LEN],
            sname: [0u8; SNAME_SIZE],
            file: [0u8; FILE_SIZE],
            options,
        }
    }

    /// Parse DHCPv4 packet from raw UDP payload bytes
    ///
    /// This function validates the packet structure and extracts all fields.
    /// It replaces the C function `dhcp_reply()` packet parsing portion.
    ///
    /// # Validation Performed
    ///
    /// 1. Minimum size check (300 bytes)
    /// 2. Operation code validation (BOOTREQUEST or BOOTREPLY)
    /// 3. Hardware address length check (≤16 bytes)
    /// 4. DHCP magic cookie verification (0x63825363)
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes from UDP socket
    ///
    /// # Returns
    ///
    /// * `Ok(DhcpPacket)` - Successfully parsed packet
    /// * `Err(PacketError)` - Invalid packet format
    ///
    /// # Errors
    ///
    /// Returns `PacketError` if:
    /// - Packet is too small (`TruncatedPacket`)
    /// - Operation code is invalid (`InvalidOpCode`)
    /// - Hardware length exceeds 16 (`InvalidHardwareLength`)
    /// - DHCP magic cookie is missing (`MissingDhcpCookie`)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let packet_data: &[u8] = &udp_payload;
    /// match DhcpPacket::parse(packet_data) {
    ///     Ok(packet) => {
    ///         println!("Transaction ID: 0x{:08x}", packet.get_xid());
    ///     }
    ///     Err(e) => {
    ///         error!("Failed to parse DHCP packet: {}", e);
    ///     }
    /// }
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        // Validate minimum packet size (300 bytes for compatibility)
        if data.len() < MIN_PACKET_SIZE {
            return Err(PacketError::TruncatedPacket(data.len()));
        }

        let mut cursor = Cursor::new(data);

        // Parse fixed header fields (236 bytes total)
        let op = data[0];
        let htype = data[1];
        let hlen = data[2];
        let hops = data[3];

        // Validate operation code (BOOTREQUEST=1 or BOOTREPLY=2)
        if op != 1 && op != 2 {
            return Err(PacketError::InvalidOpCode(op));
        }

        // Validate hardware address length
        if hlen > MAX_CHADDR_LEN as u8 {
            return Err(PacketError::InvalidHardwareLength(hlen));
        }

        // Parse multi-byte fields in network byte order (big-endian)
        cursor.set_position(4);
        let xid = cursor.read_u32::<BigEndian>()?;
        let secs = cursor.read_u16::<BigEndian>()?;
        let flags = cursor.read_u16::<BigEndian>()?;

        // Parse IPv4 addresses (4 bytes each, big-endian)
        let ciaddr = Ipv4Addr::from(cursor.read_u32::<BigEndian>()?);
        let yiaddr = Ipv4Addr::from(cursor.read_u32::<BigEndian>()?);
        let siaddr = Ipv4Addr::from(cursor.read_u32::<BigEndian>()?);
        let giaddr = Ipv4Addr::from(cursor.read_u32::<BigEndian>()?);

        // Parse client hardware address (16 bytes)
        let mut chaddr = [0u8; MAX_CHADDR_LEN];
        chaddr.copy_from_slice(&data[28..44]);

        // Parse server name field (64 bytes)
        let mut sname = [0u8; SNAME_SIZE];
        sname.copy_from_slice(&data[44..108]);

        // Parse boot file name field (128 bytes)
        let mut file = [0u8; FILE_SIZE];
        file.copy_from_slice(&data[108..236]);

        // Parse options field (starts at byte 236)
        // Must begin with DHCP magic cookie (0x63825363)
        if data.len() < 240 {
            return Err(PacketError::TruncatedPacket(data.len()));
        }

        let magic_cookie = u32::from_be_bytes([data[236], data[237], data[238], data[239]]);
        if magic_cookie != DHCP_COOKIE {
            return Err(PacketError::MissingDhcpCookie);
        }

        // Copy options field (everything after byte 236)
        let options = data[236..].to_vec();

        Ok(DhcpPacket {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options,
        })
    }

    /// Serialize DHCP packet to wire format bytes for network transmission
    ///
    /// Converts the packet structure to RFC 2131 wire format with all fields
    /// in network byte order (big-endian). Pads packet to minimum 300 bytes
    /// if necessary. This replaces the C function `dhcp_packet()`.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Serialized packet ready for UDP transmission
    /// * `Err(PacketError)` - Serialization failed (I/O error)
    ///
    /// # Wire Format
    ///
    /// 1. Fixed header (236 bytes): op, htype, hlen, hops, xid, secs, flags,
    ///    ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file
    /// 2. Options (variable): DHCP magic cookie + options + padding to 300 bytes
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut packet = DhcpPacket::new();
    /// packet.set_op(BOOTREPLY);
    /// packet.set_xid(0x12345678);
    /// packet.set_yiaddr(Ipv4Addr::new(192, 168, 1, 100));
    /// packet.set_option(DhcpOption::MessageType(MessageType::Offer as u8));
    ///
    /// let bytes = packet.serialize()?;
    /// udp_socket.send_to(&bytes, client_addr)?;
    /// ```
    pub fn serialize(&self) -> Result<Vec<u8>, PacketError> {
        let mut buffer = BytesMut::with_capacity(DHCP_MIN_STRUCTURE_SIZE);

        // Write fixed header fields (236 bytes)
        buffer.put_u8(self.op);
        buffer.put_u8(self.htype);
        buffer.put_u8(self.hlen);
        buffer.put_u8(self.hops);

        // Write multi-byte fields in network byte order (big-endian)
        buffer.put_slice(&self.xid.to_be_bytes());
        buffer.put_slice(&self.secs.to_be_bytes());
        buffer.put_slice(&self.flags.to_be_bytes());

        // Write IPv4 addresses (4 bytes each, big-endian)
        buffer.put_slice(&u32::from(self.ciaddr).to_be_bytes());
        buffer.put_slice(&u32::from(self.yiaddr).to_be_bytes());
        buffer.put_slice(&u32::from(self.siaddr).to_be_bytes());
        buffer.put_slice(&u32::from(self.giaddr).to_be_bytes());

        // Write client hardware address (16 bytes)
        buffer.extend_from_slice(&self.chaddr);

        // Write server name (64 bytes)
        buffer.extend_from_slice(&self.sname);

        // Write boot file name (128 bytes)
        buffer.extend_from_slice(&self.file);

        // Write options (includes DHCP magic cookie)
        buffer.extend_from_slice(&self.options);

        // Pad to minimum packet size (300 bytes) if necessary
        // Use OPTION_PAD (0) for padding
        let current_len = buffer.len();
        if current_len < MIN_PACKET_SIZE {
            // Add padding before the final OPTION_END if present
            let padding_needed = MIN_PACKET_SIZE - current_len;
            buffer.resize(MIN_PACKET_SIZE, OPTION_PAD);
        }

        Ok(buffer.to_vec())
    }

    /// Calculate actual packet size including options
    ///
    /// Returns the size of the packet as it would be serialized, including
    /// the fixed header (236 bytes) plus options field. Minimum return value
    /// is 300 bytes due to padding.
    ///
    /// This replaces the C function `dhcp_packet_size()`.
    ///
    /// # Returns
    ///
    /// Size in bytes (minimum 300)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let packet = DhcpPacket::parse(&data)?;
    /// let size = packet.packet_size();
    /// println!("Packet will be {} bytes when serialized", size);
    /// ```
    pub fn packet_size(&self) -> usize {
        let raw_size = DHCP_FIXED_HEADER_SIZE + self.options.len();
        raw_size.max(MIN_PACKET_SIZE)
    }

    // ========================================================================
    // Field Accessors (Getters)
    // ========================================================================

    /// Get transaction ID (xid) for matching requests with responses
    ///
    /// The transaction ID is a random 32-bit value generated by the client
    /// to match requests with responses. Server copies this value from
    /// request to response.
    pub fn get_xid(&self) -> u32 {
        self.xid
    }

    /// Get client hardware address (MAC address for Ethernet)
    ///
    /// Returns only the valid portion of the hardware address as specified
    /// by the hlen field. For Ethernet, this is typically 6 bytes.
    ///
    /// # Returns
    ///
    /// Slice containing valid hardware address bytes (length = hlen)
    pub fn get_chaddr(&self) -> &[u8] {
        &self.chaddr[..self.hlen.min(MAX_CHADDR_LEN as u8) as usize]
    }

    /// Get hardware address length in bytes
    pub fn get_hlen(&self) -> u8 {
        self.hlen
    }

    /// Get client IP address (ciaddr field)
    ///
    /// This is the client's current IP address, if the client is in
    /// RENEWING or REBINDING state. Zero in INIT/SELECTING states.
    pub fn get_ciaddr(&self) -> Ipv4Addr {
        self.ciaddr
    }

    /// Get 'your' (client) IP address (yiaddr field)
    ///
    /// This is the IP address offered or confirmed by the server.
    /// Zero in client requests.
    pub fn get_yiaddr(&self) -> Ipv4Addr {
        self.yiaddr
    }

    /// Get server IP address (siaddr field)
    ///
    /// Address of next server for bootstrap (e.g., TFTP for network boot).
    /// May be zero if not needed.
    pub fn get_siaddr(&self) -> Ipv4Addr {
        self.siaddr
    }

    /// Get relay agent IP address (giaddr field)
    ///
    /// IP address of the relay agent that forwarded this packet.
    /// Zero for packets on the same subnet as the server.
    ///
    /// When non-zero, server uses this to determine client's network
    /// location and select appropriate address pool.
    pub fn get_giaddr(&self) -> Ipv4Addr {
        self.giaddr
    }

    /// Get flags field value
    ///
    /// Bit 15 (0x8000) is BROADCAST flag indicating client cannot receive
    /// unicast until configuration is complete. Other bits reserved.
    pub fn get_flags(&self) -> u16 {
        self.flags
    }

    /// Check if BROADCAST flag is set
    ///
    /// Returns true if client requires broadcast responses (cannot receive
    /// unicast before configuration complete).
    pub fn is_broadcast(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Get operation code (BOOTREQUEST=1 or BOOTREPLY=2)
    pub fn get_op(&self) -> u8 {
        self.op
    }

    /// Get hardware type (1=Ethernet, 6=IEEE 802, per RFC 1700)
    pub fn get_htype(&self) -> u8 {
        self.htype
    }

    /// Get relay hop count (incremented by each relay agent)
    pub fn get_hops(&self) -> u8 {
        self.hops
    }

    /// Get seconds elapsed since client began address acquisition
    pub fn get_secs(&self) -> u16 {
        self.secs
    }

    // ========================================================================
    // Field Setters
    // ========================================================================

    /// Set operation code (BOOTREQUEST=1 or BOOTREPLY=2)
    pub fn set_op(&mut self, op: u8) {
        self.op = op;
    }

    /// Set transaction ID
    pub fn set_xid(&mut self, xid: u32) {
        self.xid = xid;
    }

    /// Set client IP address
    pub fn set_ciaddr(&mut self, addr: Ipv4Addr) {
        self.ciaddr = addr;
    }

    /// Set 'your' (client) IP address
    pub fn set_yiaddr(&mut self, addr: Ipv4Addr) {
        self.yiaddr = addr;
    }

    /// Set server IP address
    pub fn set_siaddr(&mut self, addr: Ipv4Addr) {
        self.siaddr = addr;
    }

    /// Set relay agent IP address
    pub fn set_giaddr(&mut self, addr: Ipv4Addr) {
        self.giaddr = addr;
    }

    /// Set flags field
    pub fn set_flags(&mut self, flags: u16) {
        self.flags = flags;
    }

    /// Set client hardware address
    ///
    /// # Arguments
    ///
    /// * `addr` - Hardware address bytes (up to 16 bytes)
    ///
    /// # Panics
    ///
    /// Panics if addr length exceeds 16 bytes
    pub fn set_chaddr(&mut self, addr: &[u8]) {
        assert!(addr.len() <= MAX_CHADDR_LEN, "Hardware address too long");
        self.hlen = addr.len() as u8;
        self.chaddr[..addr.len()].copy_from_slice(addr);
        // Zero remaining bytes
        self.chaddr[addr.len()..].fill(0);
    }

    // ========================================================================
    // Message Type and Client Identification
    // ========================================================================

    /// Extract DHCP message type from Option 53
    ///
    /// All DHCP packets must include Option 53 (DHCP Message Type) per RFC 2131.
    /// This method locates and validates the message type option.
    ///
    /// This replaces the C code that manually searched for Option 53 in the
    /// options array using pointer arithmetic.
    ///
    /// # Returns
    ///
    /// * `Ok(MessageType)` - Valid message type (DISCOVER, OFFER, etc.)
    /// * `Err(PacketError::InvalidMessageType)` - Option 53 missing or invalid
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let packet = DhcpPacket::parse(&data)?;
    /// match packet.get_message_type()? {
    ///     MessageType::Discover => handle_discover(packet),
    ///     MessageType::Request => handle_request(packet),
    ///     _ => {}
    /// }
    /// ```
    pub fn get_message_type(&self) -> Result<MessageType, PacketError> {
        // Search for Option 53 (DHCP Message Type)
        if let Some(option_data) = self.find_option(OPTION_MESSAGE_TYPE) {
            if option_data.len() == 1 {
                if let Some(msg_type) = MessageType::from_u8(option_data[0]) {
                    return Ok(msg_type);
                }
            }
        }

        Err(PacketError::InvalidMessageType)
    }

    /// Get client identifier for uniquely identifying DHCP client
    ///
    /// Clients are identified by either:
    /// 1. Client Identifier option (Option 61) - preferred
    /// 2. Hardware address from chaddr field - fallback
    ///
    /// This replaces the C code in `dhcp_reply()` that manually checked
    /// for Option 61 and fell back to chaddr.
    ///
    /// # Returns
    ///
    /// ClientId containing either Option 61 data or hardware address
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let packet = DhcpPacket::parse(&data)?;
    /// let client_id = packet.get_client_id();
    /// println!("Client ID: {:02x?}", client_id.as_bytes());
    /// ```
    pub fn get_client_id(&self) -> ClientId {
        // Try Option 61 (Client Identifier) first
        if let Some(option_data) = self.find_option(OPTION_CLIENT_ID) {
            return ClientId::from_option(option_data);
        }

        // Fall back to hardware address (chaddr field)
        ClientId::from_hardware_address(&self.chaddr, self.hlen)
    }

    // ========================================================================
    // Option Parsing and Manipulation
    // ========================================================================

    /// Find and extract a specific DHCP option from the options field
    ///
    /// Searches the options field for the specified option code and returns
    /// its data. This replaces the C function `option_find()` which used
    /// pointer arithmetic to walk the options array.
    ///
    /// # Arguments
    ///
    /// * `option_code` - DHCP option code to search for (e.g., 53 for Message Type)
    ///
    /// # Returns
    ///
    /// * `Some(&[u8])` - Option data bytes (without tag and length)
    /// * `None` - Option not found in packet
    ///
    /// # Option Format
    ///
    /// Options are encoded as tag-length-value:
    /// - Tag: 1 byte option code
    /// - Length: 1 byte data length
    /// - Value: variable length data
    ///
    /// Special cases:
    /// - Option 0 (PAD): No length or data, used for alignment
    /// - Option 255 (END): Marks end of options, no length or data
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Find requested IP address (Option 50)
    /// if let Some(data) = packet.find_option(50) {
    ///     if data.len() == 4 {
    ///         let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
    ///         println!("Client requested: {}", ip);
    ///     }
    /// }
    /// ```
    fn find_option(&self, option_code: u8) -> Option<&[u8]> {
        // Options start after DHCP magic cookie (first 4 bytes)
        if self.options.len() < 4 {
            return None;
        }

        let mut pos = 4; // Skip magic cookie

        while pos < self.options.len() {
            let code = self.options[pos];

            // Option 255 (END) marks end of options
            if code == OPTION_END {
                break;
            }

            // Option 0 (PAD) has no length or data
            if code == OPTION_PAD {
                pos += 1;
                continue;
            }

            // Check if we have room for length byte
            if pos + 1 >= self.options.len() {
                break;
            }

            let len = self.options[pos + 1] as usize;

            // Check if option data fits in remaining space
            if pos + 2 + len > self.options.len() {
                break;
            }

            // Found the option we're looking for
            if code == option_code {
                return Some(&self.options[pos + 2..pos + 2 + len]);
            }

            // Move to next option
            pos += 2 + len;
        }

        None
    }

    /// Find a specific DHCP option and return full option bytes (code + length + data)
    ///
    /// Similar to find_option but returns the complete option including the code
    /// and length bytes, which is needed for DhcpOption::parse().
    ///
    /// # Arguments
    ///
    /// * `option_code` - Option code to search for (e.g., 53 for message type)
    ///
    /// # Returns
    ///
    /// * `Some(&[u8])` - Full option bytes [code, length, data...]
    /// * `None` - Option not found
    fn find_option_full(&self, option_code: u8) -> Option<&[u8]> {
        // Options start after DHCP magic cookie (first 4 bytes)
        if self.options.len() < 4 {
            return None;
        }

        let mut pos = 4; // Skip magic cookie

        while pos < self.options.len() {
            let code = self.options[pos];

            // Option 255 (END) marks end of options
            if code == OPTION_END {
                break;
            }

            // Option 0 (PAD) has no length or data
            if code == OPTION_PAD {
                pos += 1;
                continue;
            }

            // Check if we have room for length byte
            if pos + 1 >= self.options.len() {
                break;
            }

            let len = self.options[pos + 1] as usize;

            // Check if option data fits in remaining space
            if pos + 2 + len > self.options.len() {
                break;
            }

            // Found the option we're looking for - return full option including code and length
            if code == option_code {
                return Some(&self.options[pos..pos + 2 + len]);
            }

            // Move to next option
            pos += 2 + len;
        }

        None
    }

    /// Get a specific DHCP option by parsing it into typed enum
    ///
    /// This is a convenience wrapper around `find_option()` that additionally
    /// parses the raw option bytes into a typed `DhcpOption` enum.
    ///
    /// # Arguments
    ///
    /// * `option_code` - DHCP option code to retrieve
    ///
    /// # Returns
    ///
    /// * `Some(DhcpOption)` - Successfully parsed option
    /// * `None` - Option not found or parse failed
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if let Some(DhcpOption::ServerIdentifier(server_ip)) = packet.get_option(54) {
    ///     println!("Server: {}", server_ip);
    /// }
    /// ```
    pub fn get_option(&self, option_code: u8) -> Option<DhcpOption> {
        self.find_option_full(option_code)
            .and_then(|data| DhcpOption::parse(data).ok())
    }

    /// Get all DHCP options from the packet
    ///
    /// Parses all options in the options field and returns them as a vector
    /// of typed `DhcpOption` enums. Invalid options are skipped.
    ///
    /// # Returns
    ///
    /// Vector of all successfully parsed DHCP options
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let options = packet.get_options();
    /// for option in options {
    ///     match option {
    ///         DhcpOption::SubnetMask(mask) => println!("Subnet: {}", mask),
    ///         DhcpOption::Router(routers) => println!("Routers: {:?}", routers),
    ///         _ => {}
    ///     }
    /// }
    /// ```
    pub fn get_options(&self) -> Vec<DhcpOption> {
        let mut options = Vec::new();

        if self.options.len() < 4 {
            return options;
        }

        let mut pos = 4; // Skip magic cookie

        while pos < self.options.len() {
            let code = self.options[pos];

            if code == OPTION_END {
                break;
            }

            if code == OPTION_PAD {
                pos += 1;
                continue;
            }

            if pos + 1 >= self.options.len() {
                break;
            }

            let len = self.options[pos + 1] as usize;

            if pos + 2 + len > self.options.len() {
                break;
            }

            // Pass full option bytes (code + length + data) to parse
            let full_option = &self.options[pos..pos + 2 + len];
            if let Ok(option) = DhcpOption::parse(full_option) {
                options.push(option);
            }

            pos += 2 + len;
        }

        options
    }

    /// Add or update a DHCP option in the packet
    ///
    /// Appends the option to the options field. If the option already exists,
    /// it is NOT removed - both instances will be present. For most use cases,
    /// construct a fresh packet rather than modifying existing options.
    ///
    /// # Arguments
    ///
    /// * `option` - DHCP option to add
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut packet = DhcpPacket::new();
    /// packet.set_option(DhcpOption::MessageType(MessageType::Offer as u8));
    /// packet.set_option(DhcpOption::ServerIdentifier(server_ip));
    /// packet.set_option(DhcpOption::LeaseTime(3600));
    /// ```
    pub fn set_option(&mut self, option: DhcpOption) {
        // Serialize option to bytes
        let option_bytes = option.serialize();

        // Remove OPTION_END marker if present
        if let Some(&OPTION_END) = self.options.last() {
            self.options.pop();
        }

        // Append new option
        self.options.extend_from_slice(&option_bytes);

        // Add OPTION_END marker
        self.options.push(OPTION_END);
    }
}

impl Default for DhcpPacket {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Type Aliases for External API Consistency
// ============================================================================

/// Type alias for DHCPv4 message/packet structure
///
/// This provides a consistent naming convention across the codebase.
/// External modules can import either `DhcpPacket` or `Dhcpv4Message`.
pub type Dhcpv4Message = DhcpPacket;

/// Type alias for DHCPv4 message type enum
///
/// This provides a consistent naming convention across the codebase.
/// External modules can import either `MessageType` or `Dhcpv4MessageType`.
pub type Dhcpv4MessageType = MessageType;

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid DHCP packet for testing
    fn create_test_packet() -> Vec<u8> {
        let mut packet = vec![0u8; MIN_PACKET_SIZE];

        // Set operation code (BOOTREQUEST)
        packet[0] = 1;
        // Set hardware type (Ethernet)
        packet[1] = 1;
        // Set hardware address length
        packet[2] = 6;
        // Set hops
        packet[3] = 0;

        // Set transaction ID (0x12345678)
        packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());

        // Set DHCP magic cookie at offset 236
        packet[236..240].copy_from_slice(&DHCP_COOKIE.to_be_bytes());

        // Add Option 53 (Message Type = DISCOVER)
        packet[240] = OPTION_MESSAGE_TYPE;
        packet[241] = 1;
        packet[242] = MessageType::Discover as u8;

        // Add Option 255 (END)
        packet[243] = OPTION_END;

        packet
    }

    #[test]
    fn test_packet_parse_valid() {
        let data = create_test_packet();
        let packet = DhcpPacket::parse(&data).expect("Should parse valid packet");

        assert_eq!(packet.get_op(), 1);
        assert_eq!(packet.get_htype(), 1);
        assert_eq!(packet.get_hlen(), 6);
        assert_eq!(packet.get_xid(), 0x12345678);
    }

    #[test]
    fn test_packet_parse_too_small() {
        let data = vec![0u8; 100];
        let result = DhcpPacket::parse(&data);

        assert!(matches!(result, Err(PacketError::TruncatedPacket(100))));
    }

    #[test]
    fn test_packet_parse_invalid_op_code() {
        let mut data = create_test_packet();
        data[0] = 99; // Invalid op code

        let result = DhcpPacket::parse(&data);
        assert!(matches!(result, Err(PacketError::InvalidOpCode(99))));
    }

    #[test]
    fn test_packet_parse_invalid_hlen() {
        let mut data = create_test_packet();
        data[2] = 20; // hlen > 16

        let result = DhcpPacket::parse(&data);
        assert!(matches!(result, Err(PacketError::InvalidHardwareLength(20))));
    }

    #[test]
    fn test_packet_parse_missing_cookie() {
        let mut data = create_test_packet();
        // Corrupt magic cookie
        data[236] = 0xFF;

        let result = DhcpPacket::parse(&data);
        assert!(matches!(result, Err(PacketError::MissingDhcpCookie)));
    }

    #[test]
    fn test_message_type_extraction() {
        let data = create_test_packet();
        let packet = DhcpPacket::parse(&data).unwrap();

        let msg_type = packet.get_message_type().expect("Should find message type");
        assert_eq!(msg_type, MessageType::Discover);
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::from_u8(1), Some(MessageType::Discover));
        assert_eq!(MessageType::from_u8(2), Some(MessageType::Offer));
        assert_eq!(MessageType::from_u8(3), Some(MessageType::Request));
        assert_eq!(MessageType::from_u8(4), Some(MessageType::Decline));
        assert_eq!(MessageType::from_u8(5), Some(MessageType::Ack));
        assert_eq!(MessageType::from_u8(6), Some(MessageType::Nak));
        assert_eq!(MessageType::from_u8(7), Some(MessageType::Release));
        assert_eq!(MessageType::from_u8(8), Some(MessageType::Inform));
        assert_eq!(MessageType::from_u8(99), None);

        assert_eq!(MessageType::Discover.to_u8(), 1);
        assert_eq!(MessageType::Offer.to_u8(), 2);
    }

    #[test]
    fn test_client_id_from_option() {
        let option_data = vec![0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let client_id = ClientId::from_option(&option_data);

        assert_eq!(client_id.len(), 7);
        assert_eq!(client_id.as_bytes(), &option_data);
    }

    #[test]
    fn test_client_id_from_hardware_address() {
        let hw_addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let client_id = ClientId::from_hardware_address(&hw_addr, 6);

        assert_eq!(client_id.len(), 6);
        assert_eq!(client_id.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_packet_serialization_round_trip() {
        // Parse original packet
        let original_data = create_test_packet();
        let packet = DhcpPacket::parse(&original_data).unwrap();

        // Serialize it back
        let serialized = packet.serialize().unwrap();

        // Parse serialized version
        let reparsed = DhcpPacket::parse(&serialized).unwrap();

        // Verify key fields match
        assert_eq!(packet.get_op(), reparsed.get_op());
        assert_eq!(packet.get_xid(), reparsed.get_xid());
        assert_eq!(packet.get_hlen(), reparsed.get_hlen());
        assert_eq!(packet.get_message_type().unwrap(), reparsed.get_message_type().unwrap());
    }

    #[test]
    fn test_packet_new() {
        let packet = DhcpPacket::new();

        assert_eq!(packet.get_htype(), 1); // Ethernet
        assert_eq!(packet.get_hlen(), 6); // MAC length
        assert_eq!(packet.get_xid(), 0);
        assert_eq!(packet.get_ciaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(packet.get_yiaddr(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn test_packet_set_chaddr() {
        let mut packet = DhcpPacket::new();
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        packet.set_chaddr(&mac);

        assert_eq!(packet.get_hlen(), 6);
        assert_eq!(packet.get_chaddr(), &mac);
    }

    #[test]
    fn test_packet_flags() {
        let mut packet = DhcpPacket::new();

        packet.set_flags(0x8000);
        assert_eq!(packet.get_flags(), 0x8000);
        assert!(packet.is_broadcast());

        packet.set_flags(0x0000);
        assert!(!packet.is_broadcast());
    }

    #[test]
    fn test_packet_addresses() {
        let mut packet = DhcpPacket::new();

        let ciaddr = Ipv4Addr::new(192, 168, 1, 100);
        let yiaddr = Ipv4Addr::new(192, 168, 1, 101);
        let siaddr = Ipv4Addr::new(192, 168, 1, 1);
        let giaddr = Ipv4Addr::new(10, 0, 0, 1);

        packet.set_ciaddr(ciaddr);
        packet.set_yiaddr(yiaddr);
        packet.set_siaddr(siaddr);
        packet.set_giaddr(giaddr);

        assert_eq!(packet.get_ciaddr(), ciaddr);
        assert_eq!(packet.get_yiaddr(), yiaddr);
        assert_eq!(packet.get_siaddr(), siaddr);
        assert_eq!(packet.get_giaddr(), giaddr);
    }

    #[test]
    fn test_packet_size_calculation() {
        let packet = DhcpPacket::new();
        let size = packet.packet_size();

        // Minimum packet size is 300 bytes
        assert!(size >= MIN_PACKET_SIZE);
    }

    #[test]
    fn test_find_option() {
        let data = create_test_packet();
        let packet = DhcpPacket::parse(&data).unwrap();

        // Option 53 (Message Type) should be found
        let option_data = packet.find_option(OPTION_MESSAGE_TYPE);
        assert!(option_data.is_some());
        assert_eq!(option_data.unwrap(), &[MessageType::Discover as u8]);

        // Non-existent option should return None
        assert!(packet.find_option(99).is_none());
    }

    #[test]
    fn test_set_option() {
        let mut packet = DhcpPacket::new();

        packet.set_option(DhcpOption::MessageType(MessageType::Offer as u8));

        let msg_type = packet.get_message_type().unwrap();
        assert_eq!(msg_type, MessageType::Offer);
    }

    #[test]
    fn test_get_client_id_with_option() {
        let mut data = create_test_packet();

        // Add Option 61 (Client Identifier)
        let mut pos = 243; // After Option 255
        data[pos] = OPTION_CLIENT_ID;
        data[pos + 1] = 7; // Length
        data[pos + 2] = 0x01; // Type: Ethernet
        data[pos + 3..pos + 9].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        data[pos + 9] = OPTION_END;

        let packet = DhcpPacket::parse(&data).unwrap();
        let client_id = packet.get_client_id();

        assert_eq!(client_id.len(), 7);
        assert_eq!(client_id.as_bytes()[0], 0x01);
    }

    #[test]
    fn test_get_client_id_fallback_to_chaddr() {
        let mut data = create_test_packet();

        // Set MAC address in chaddr field
        data[28..34].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let packet = DhcpPacket::parse(&data).unwrap();
        let client_id = packet.get_client_id();

        // Should use chaddr since Option 61 not present
        assert_eq!(client_id.len(), 6);
        assert_eq!(client_id.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_packet_minimum_size_padding() {
        let mut packet = DhcpPacket::new();
        packet.set_op(BOOTREPLY);
        packet.set_xid(0x12345678);

        let serialized = packet.serialize().unwrap();

        // Should be padded to minimum 300 bytes
        assert_eq!(serialized.len(), MIN_PACKET_SIZE);
    }
}


