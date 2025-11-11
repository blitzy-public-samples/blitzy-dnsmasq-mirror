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
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! `DHCPv4` Protocol Constants and Wire Format Structures
//!
//! This module provides type-safe Rust implementations of `DHCPv4` protocol constants,
//! message types, option codes, and the wire-format packet structure per RFC 2131
//! and RFC 2132. All numeric values maintain byte-identical compatibility with the
//! C implementation for network protocol compliance.
//!
//! # Core Components
//!
//! - **`MessageType`**: DHCP message type enum (DISCOVER, OFFER, REQUEST, etc.)
//! - **`OptionCode`**: Type-safe DHCP option codes with exhaustive matching
//! - **`DhcpPacket`**: Wire-format packet structure with repr(C) for binary compatibility
//! - **`SuboptionCode`**: Relay agent information suboption codes
//! - **`PxeSuboption`**: PXE boot suboption codes
//!
//! # Memory Safety
//!
//! Replaces C's preprocessor macros and manual bounds checking with:
//! - Rust enums providing type safety and exhaustive pattern matching
//! - Compile-time bounds checking for fixed-size arrays
//! - `Ipv4Addr` type eliminating manual byte order conversions
//! - No manual pointer arithmetic or buffer overflow vulnerabilities
//!
//! # RFC Compliance
//!
//! - RFC 2131: Dynamic Host Configuration Protocol (packet format, message types)
//! - RFC 2132: DHCP Options and BOOTP Vendor Extensions (option codes)
//! - RFC 3027: Relay Agent Information Option (suboption codes)
//! - RFC 3393: Subscriber-ID Suboption
//! - RFC 3527: Link Selection Suboption
//! - RFC 5107: Server Override Suboption
//! - PXE Specification v2.1: PXE boot options

use std::net::Ipv4Addr;

// ============================================================================
// Port Number Constants
// ============================================================================

/// Standard UDP port for DHCP server (67) per RFC 2131 Section 4.1.
///
/// Servers bind to this port to receive DHCPDISCOVER, DHCPREQUEST, DHCPRELEASE,
/// DHCPDECLINE, and DHCPINFORM messages from clients.
pub const DHCP_SERVER_PORT: u16 = 67;

/// Standard UDP port for DHCP client (68) per RFC 2131 Section 4.1.
///
/// Clients bind to this port to receive DHCPOFFER, DHCPACK, and DHCPNAK
/// messages from servers.
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Alternate DHCP server port (1067).
///
/// Non-standard port used when standard port 67 conflicts with other services.
/// Configured via --dhcp-alternate-port command-line option.
pub const DHCP_SERVER_ALTPORT: u16 = 1067;

/// Alternate DHCP client port (1068).
///
/// Non-standard port paired with `DHCP_SERVER_ALTPORT` for alternate operation.
pub const DHCP_CLIENT_ALTPORT: u16 = 1068;

/// PXE (Pre-boot Execution Environment) server port (4011).
///
/// Well-known port for PXE boot servers per PXE specification. Used for proxy
/// DHCP mode where PXE-specific options are served separately from IP allocation.
pub const PXE_PORT: u16 = 4011;

// ============================================================================
// Protocol Constants
// ============================================================================

/// DHCP magic cookie (0x63825363) per RFC 2131 Section 3.
///
/// First four bytes of options field must contain this value in network byte
/// order (99, 130, 83, 99 decimal). Distinguishes DHCP packets from legacy BOOTP.
pub const DHCP_COOKIE: u32 = 0x6382_5363;

/// Minimum `DHCPv4` packet size (300 bytes).
///
/// Enforced to work around Linux in-kernel DHCP client bug. Packets shorter
/// than this are padded with `OPTION_PAD` bytes before transmission.
pub const MIN_PACKETSZ: usize = 300;

/// Maximum size for DHCP option value buffer (256 bytes).
///
/// Buffer size to hold one DHCP option with maximum value length (255 bytes)
/// plus one terminating zero byte for string safety.
pub const DHCP_BUFF_SZ: usize = 256;

/// BOOTP/DHCP request operation code (1).
///
/// Value for DhcpPacket.op field indicating message is from client to server.
pub const BOOTREQUEST: u8 = 1;

/// BOOTP/DHCP reply operation code (2).
///
/// Value for DhcpPacket.op field indicating message is from server to client.
pub const BOOTREPLY: u8 = 2;

/// Maximum client hardware address length (16 bytes).
///
/// Size of chaddr field in `DhcpPacket` per RFC 2131 Section 2.
pub const DHCP_CHADDR_MAX: usize = 16;

/// Broadband Forum IANA enterprise number (3561).
///
/// Used in vendor-identifying options (124, 125) for DSL Forum equipment.
pub const BRDBAND_FORUM_IANA: u32 = 3561;

// ============================================================================
// DHCP Message Type Enum
// ============================================================================

/// DHCP message types per RFC 2131 Section 3.1.
///
/// Values carried in `OPTION_MESSAGE_TYPE` (53) to identify DHCP message purpose.
/// Each message type defines specific required and optional options.
///
/// Note: Variant names intentionally match RFC 2131 and C implementation naming.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum MessageType {
    /// DHCP Discover (1): Broadcast by client to locate available servers.
    DHCPDISCOVER = 1,
    /// DHCP Offer (2): Server response to DISCOVER with offered IP address.
    DHCPOFFER = 2,
    /// DHCP Request (3): Client requests offered IP or renews existing lease.
    DHCPREQUEST = 3,
    /// DHCP Decline (4): Client reports offered IP is already in use (ARP conflict).
    DHCPDECLINE = 4,
    /// DHCP Acknowledgment (5): Server confirms IP allocation.
    DHCPACK = 5,
    /// DHCP Negative Acknowledgment (6): Server rejects REQUEST.
    DHCPNAK = 6,
    /// DHCP Release (7): Client voluntarily releases IP before lease expiry.
    DHCPRELEASE = 7,
    /// DHCP Inform (8): Client requests configuration parameters without IP allocation.
    DHCPINFORM = 8,
}

impl MessageType {
    /// Converts a u8 value to `MessageType`, returning None for invalid values.
    #[must_use] 
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(MessageType::DHCPDISCOVER),
            2 => Some(MessageType::DHCPOFFER),
            3 => Some(MessageType::DHCPREQUEST),
            4 => Some(MessageType::DHCPDECLINE),
            5 => Some(MessageType::DHCPACK),
            6 => Some(MessageType::DHCPNAK),
            7 => Some(MessageType::DHCPRELEASE),
            8 => Some(MessageType::DHCPINFORM),
            _ => None,
        }
    }

    /// Converts `MessageType` to u8 value for wire encoding.
    #[must_use] 
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// DHCP Option Code Enum
// ============================================================================

/// DHCP option codes per RFC 2132.
///
/// Type-safe representation of DHCP option codes with exhaustive matching.
/// Prevents use of invalid option numbers and enables compile-time verification.
///
/// Note: Variant names intentionally match RFC 2132 and C implementation naming.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum OptionCode {
    /// Padding option (0): Used to pad options field or align options.
    OPTION_PAD = 0,
    /// Subnet mask (1): 4-byte IPv4 subnet mask.
    OPTION_NETMASK = 1,
    /// Router/default gateway (3): List of router IPv4 addresses.
    OPTION_ROUTER = 3,
    /// Time server (4): List of RFC 868 time server IPv4 addresses.
    OPTION_TIME_SERVER = 4,
    /// Domain name server (6): List of DNS server IPv4 addresses.
    OPTION_DNSSERVER = 6,
    /// Hostname (12): Client's hostname (ASCII string).
    OPTION_HOSTNAME = 12,
    /// Domain name (15): DNS domain name for client (ASCII string).
    OPTION_DOMAINNAME = 15,
    /// Interface MTU (26): 2-byte interface MTU size.
    OPTION_MTU = 26,
    /// Broadcast address (28): 4-byte IPv4 broadcast address for subnet.
    OPTION_BROADCAST = 28,
    /// Network Time Protocol servers (42): List of NTP server IPv4 addresses.
    OPTION_NTP_SERVER = 42,
    /// Vendor-specific information (43): Vendor-specific data.
    OPTION_VENDOR_CLASS_OPT = 43,
    /// Requested IP address (50): 4-byte IPv4 address client requests.
    OPTION_REQUESTED_IP = 50,
    /// IP address lease time (51): 4-byte lease duration in seconds.
    OPTION_LEASE_TIME = 51,
    /// Option overload (52): Indicates sname/file fields contain options.
    OPTION_OVERLOAD = 52,
    /// DHCP message type (53): 1-byte message type (DISCOVER, OFFER, etc.).
    OPTION_MESSAGE_TYPE = 53,
    /// Server identifier (54): 4-byte IPv4 address identifying DHCP server.
    OPTION_SERVER_IDENTIFIER = 54,
    /// Parameter request list (55): List of option codes client requests.
    OPTION_REQUESTED_OPTIONS = 55,
    /// Message (56): ASCII string error message from server.
    OPTION_MESSAGE = 56,
    /// Maximum DHCP message size (57): 2-byte maximum message size.
    OPTION_MAXMESSAGE = 57,
    /// Renewal time value T1 (58): 4-byte seconds until RENEWING state.
    OPTION_T1 = 58,
    /// Rebinding time value T2 (59): 4-byte seconds until REBINDING state.
    OPTION_T2 = 59,
    /// Vendor class identifier (60): ASCII string identifying client vendor.
    OPTION_VENDOR_ID = 60,
    /// Client identifier (61): Unique client identifier (type + data).
    OPTION_CLIENT_ID = 61,
    /// TFTP server name (66): ASCII string hostname of TFTP server.
    OPTION_SNAME = 66,
    /// Boot filename (67): ASCII string boot file pathname.
    OPTION_FILENAME = 67,
    /// User class (77): Client-defined classification data.
    OPTION_USER_CLASS = 77,
    /// Rapid commit (80): Enables 2-message exchange.
    OPTION_RAPID_COMMIT = 80,
    /// Client FQDN (81): Client fully-qualified domain name for DDNS.
    OPTION_CLIENT_FQDN = 81,
    /// Relay agent information (82): Sub-options added by relay agents.
    OPTION_AGENT_ID = 82,
    /// Client system architecture (93): 2-byte PXE architecture type.
    OPTION_ARCH = 93,
    /// Client machine identifier (97): 17-byte UUID for PXE client.
    OPTION_PXE_UUID = 97,
    /// Subnet selection (118): 4-byte IPv4 subnet address.
    OPTION_SUBNET_SELECT = 118,
    /// Domain search list (119): Compressed domain name list for DNS search.
    OPTION_DOMAIN_SEARCH = 119,
    /// SIP servers (120): List of SIP server addresses or names.
    OPTION_SIP_SERVER = 120,
    /// Vendor-identifying vendor class (124): Enterprise number + vendor data.
    OPTION_VENDOR_IDENT = 124,
    /// Vendor-identifying vendor-specific (125): Enterprise number + sub-options.
    OPTION_VENDOR_IDENT_OPT = 125,
    /// End option (255): Marks end of options in packet.
    OPTION_END = 255,
}

impl OptionCode {
    /// Converts a u8 value to `OptionCode`, returning None for invalid values.
    #[must_use] 
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(OptionCode::OPTION_PAD),
            1 => Some(OptionCode::OPTION_NETMASK),
            3 => Some(OptionCode::OPTION_ROUTER),
            4 => Some(OptionCode::OPTION_TIME_SERVER),
            6 => Some(OptionCode::OPTION_DNSSERVER),
            12 => Some(OptionCode::OPTION_HOSTNAME),
            15 => Some(OptionCode::OPTION_DOMAINNAME),
            26 => Some(OptionCode::OPTION_MTU),
            28 => Some(OptionCode::OPTION_BROADCAST),
            42 => Some(OptionCode::OPTION_NTP_SERVER),
            43 => Some(OptionCode::OPTION_VENDOR_CLASS_OPT),
            50 => Some(OptionCode::OPTION_REQUESTED_IP),
            51 => Some(OptionCode::OPTION_LEASE_TIME),
            52 => Some(OptionCode::OPTION_OVERLOAD),
            53 => Some(OptionCode::OPTION_MESSAGE_TYPE),
            54 => Some(OptionCode::OPTION_SERVER_IDENTIFIER),
            55 => Some(OptionCode::OPTION_REQUESTED_OPTIONS),
            56 => Some(OptionCode::OPTION_MESSAGE),
            57 => Some(OptionCode::OPTION_MAXMESSAGE),
            58 => Some(OptionCode::OPTION_T1),
            59 => Some(OptionCode::OPTION_T2),
            60 => Some(OptionCode::OPTION_VENDOR_ID),
            61 => Some(OptionCode::OPTION_CLIENT_ID),
            66 => Some(OptionCode::OPTION_SNAME),
            67 => Some(OptionCode::OPTION_FILENAME),
            77 => Some(OptionCode::OPTION_USER_CLASS),
            80 => Some(OptionCode::OPTION_RAPID_COMMIT),
            81 => Some(OptionCode::OPTION_CLIENT_FQDN),
            82 => Some(OptionCode::OPTION_AGENT_ID),
            93 => Some(OptionCode::OPTION_ARCH),
            97 => Some(OptionCode::OPTION_PXE_UUID),
            118 => Some(OptionCode::OPTION_SUBNET_SELECT),
            119 => Some(OptionCode::OPTION_DOMAIN_SEARCH),
            120 => Some(OptionCode::OPTION_SIP_SERVER),
            124 => Some(OptionCode::OPTION_VENDOR_IDENT),
            125 => Some(OptionCode::OPTION_VENDOR_IDENT_OPT),
            255 => Some(OptionCode::OPTION_END),
            _ => None,
        }
    }

    /// Converts `OptionCode` to u8 value for wire encoding.
    #[must_use] 
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// Relay Agent Suboption Codes
// ============================================================================

/// Relay agent information suboption codes (option 82) per RFC 3027.
///
/// Sub-options appear within `OPTION_AGENT_ID` data field, added by DHCP
/// relay agents to provide client location information.
///
/// Note: Variant names intentionally match RFC 3027 and C implementation naming.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum SuboptionCode {
    /// Circuit ID (1): Identifies relay agent's circuit (port, VLAN).
    SUBOPT_CIRCUIT_ID = 1,
    /// Remote ID (2): Identifies relay agent or remote client.
    SUBOPT_REMOTE_ID = 2,
    /// Subnet selection (5): 4-byte IPv4 subnet address per RFC 3527.
    SUBOPT_SUBNET_SELECT = 5,
    /// Subscriber ID (6): Subscriber identifier per RFC 3393.
    SUBOPT_SUBSCR_ID = 6,
    /// Server override (11): List of DHCP server addresses per RFC 5107.
    SUBOPT_SERVER_OR = 11,
}

impl SuboptionCode {
    /// Converts a u8 value to `SuboptionCode`, returning None for invalid values.
    #[must_use] 
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(SuboptionCode::SUBOPT_CIRCUIT_ID),
            2 => Some(SuboptionCode::SUBOPT_REMOTE_ID),
            5 => Some(SuboptionCode::SUBOPT_SUBNET_SELECT),
            6 => Some(SuboptionCode::SUBOPT_SUBSCR_ID),
            11 => Some(SuboptionCode::SUBOPT_SERVER_OR),
            _ => None,
        }
    }

    /// Converts `SuboptionCode` to u8 value for wire encoding.
    #[must_use] 
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// PXE Suboption Codes
// ============================================================================

/// PXE boot suboption codes (option 43) per PXE specification v2.1.
///
/// Sub-options appear within `OPTION_VENDOR_CLASS_OPT` data field for PXE boot.
///
/// Note: Variant names intentionally match PXE specification and C implementation naming.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum PxeSuboption {
    /// PXE discovery control (6): Flags controlling discovery behavior.
    SUBOPT_PXE_DISCOVERY = 6,
    /// PXE boot servers (8): List of boot server addresses by type.
    SUBOPT_PXE_SERVERS = 8,
    /// PXE boot menu (9): Boot menu entries with descriptions.
    SUBOPT_PXE_MENU = 9,
    /// PXE menu prompt (10): Timeout and prompt string for boot menu.
    SUBOPT_PXE_MENU_PROMPT = 10,
    /// PXE boot item (71): Boot menu item type and layer.
    SUBOPT_PXE_BOOT_ITEM = 71,
}

impl PxeSuboption {
    /// Converts a u8 value to `PxeSuboption`, returning None for invalid values.
    #[must_use] 
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            6 => Some(PxeSuboption::SUBOPT_PXE_DISCOVERY),
            8 => Some(PxeSuboption::SUBOPT_PXE_SERVERS),
            9 => Some(PxeSuboption::SUBOPT_PXE_MENU),
            10 => Some(PxeSuboption::SUBOPT_PXE_MENU_PROMPT),
            71 => Some(PxeSuboption::SUBOPT_PXE_BOOT_ITEM),
            _ => None,
        }
    }

    /// Converts `PxeSuboption` to u8 value for wire encoding.
    #[must_use] 
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// DHCP Packet Wire Format Structure
// ============================================================================

/// `DHCPv4` wire-format packet structure per RFC 2131 Section 2.
///
/// Represents the complete DHCPv4/BOOTP packet format transmitted over UDP,
/// including 236-byte fixed header and 312-byte variable-length options field,
/// for a total size of 548 bytes.
///
/// # Memory Layout
///
/// Total size: 548 bytes (236 fixed + 312 options)
/// - Bytes 0-3: op, htype, hlen, hops
/// - Bytes 4-7: xid (transaction ID)
/// - Bytes 8-11: secs, flags
/// - Bytes 12-15: ciaddr (client IP)
/// - Bytes 16-19: yiaddr (your IP)
/// - Bytes 20-23: siaddr (server IP)
/// - Bytes 24-27: giaddr (gateway IP)
/// - Bytes 28-43: chaddr (client hardware address, 16 bytes)
/// - Bytes 44-107: sname (server hostname, 64 bytes)
/// - Bytes 108-235: file (boot filename, 128 bytes)
/// - Bytes 236-547: options (312 bytes)
///
/// # Binary Compatibility
///
/// Uses `#[repr(C)]` to ensure identical memory layout to C struct for
/// network transmission. All multi-byte fields use network byte order (big-endian).
///
/// # RFC Compliance
///
/// - RFC 2131 Section 2: Packet format definition
/// - RFC 2132: Options field format
/// - RFC 951: BOOTP compatibility
#[repr(C)]
#[derive(Clone)]
pub struct DhcpPacket {
    /// Message operation code: BOOTREQUEST (1) or BOOTREPLY (2).
    pub op: u8,
    
    /// Hardware address type (1=Ethernet).
    pub htype: u8,
    
    /// Hardware address length in bytes (6 for Ethernet MAC).
    pub hlen: u8,
    
    /// Hop count incremented by relay agents.
    pub hops: u8,
    
    /// Transaction ID (random 32-bit value, network byte order).
    pub xid: u32,
    
    /// Seconds elapsed since client began address acquisition (network byte order).
    pub secs: u16,
    
    /// Flags field (0x8000=BROADCAST flag, network byte order).
    pub flags: u16,
    
    /// Client IP address (filled when client has valid IP).
    pub ciaddr: Ipv4Addr,
    
    /// "Your" (client) IP address (filled by server in offer/ack).
    pub yiaddr: Ipv4Addr,
    
    /// Next server IP address (TFTP server for boot).
    pub siaddr: Ipv4Addr,
    
    /// Relay agent (gateway) IP address.
    pub giaddr: Ipv4Addr,
    
    /// Client hardware address (MAC for Ethernet), 16 bytes.
    pub chaddr: [u8; DHCP_CHADDR_MAX],
    
    /// Server hostname (64 bytes, NUL-terminated ASCII).
    pub sname: [u8; 64],
    
    /// Boot filename (128 bytes, NUL-terminated ASCII).
    pub file: [u8; 128],
    
    /// Options field (312 bytes): starts with `DHCP_COOKIE`, ends with `OPTION_END`.
    pub options: [u8; 312],
}

impl DhcpPacket {
    /// Creates a new zero-initialized `DhcpPacket`.
    ///
    /// All fields are set to zero/unspecified. Caller must populate required
    /// fields before transmission.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            op: 0,
            htype: 0,
            hlen: 0,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; DHCP_CHADDR_MAX],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: [0u8; 312],
        }
    }

    /// Deserializes a `DhcpPacket` from raw bytes received from network.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw packet bytes (minimum 236 bytes for fixed header)
    ///
    /// # Returns
    ///
    /// - `Ok(DhcpPacket)` if bytes are valid and sufficient length
    /// - `Err(String)` if bytes are too short or invalid format
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice is shorter than the minimum DHCP packet size (236 bytes).
    ///
    /// # Safety
    ///
    /// Performs bounds checking before accessing byte slices. All multi-byte
    /// fields are converted from network byte order to host byte order.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 236 {
            return Err(format!(
                "Packet too short: {} bytes (minimum 236 required)",
                bytes.len()
            ));
        }

        let mut packet = Self::new();

        // Parse fixed header fields (bytes 0-235)
        packet.op = bytes[0];
        packet.htype = bytes[1];
        packet.hlen = bytes[2];
        packet.hops = bytes[3];
        
        // Parse 32-bit xid in network byte order
        packet.xid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        
        // Parse 16-bit secs and flags in network byte order
        packet.secs = u16::from_be_bytes([bytes[8], bytes[9]]);
        packet.flags = u16::from_be_bytes([bytes[10], bytes[11]]);
        
        // Parse IPv4 addresses using Ipv4Addr::from() which expects network byte order
        packet.ciaddr = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        packet.yiaddr = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
        packet.siaddr = Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23]);
        packet.giaddr = Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]);
        
        // Copy chaddr (16 bytes)
        packet.chaddr.copy_from_slice(&bytes[28..44]);
        
        // Copy sname (64 bytes)
        packet.sname.copy_from_slice(&bytes[44..108]);
        
        // Copy file (128 bytes)
        packet.file.copy_from_slice(&bytes[108..236]);
        
        // Copy options (remaining bytes up to 312, or less if packet is smaller)
        let options_len = (bytes.len() - 236).min(312);
        packet.options[..options_len].copy_from_slice(&bytes[236..236 + options_len]);

        Ok(packet)
    }

    /// Serializes `DhcpPacket` to raw bytes for network transmission.
    ///
    /// # Returns
    ///
    /// Vector of 548 bytes containing the complete packet in network byte order.
    /// All multi-byte fields are converted to big-endian before serialization.
    ///
    /// # Padding
    ///
    /// If packet would be smaller than `MIN_PACKETSZ` (300 bytes), caller should
    /// pad options field with `OPTION_PAD` bytes before calling this method.
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(548);

        // Write fixed header fields (bytes 0-3)
        bytes.push(self.op);
        bytes.push(self.htype);
        bytes.push(self.hlen);
        bytes.push(self.hops);
        
        // Write xid in network byte order
        bytes.extend_from_slice(&self.xid.to_be_bytes());
        
        // Write secs and flags in network byte order
        bytes.extend_from_slice(&self.secs.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        
        // Write IPv4 addresses in network byte order (Ipv4Addr::octets() returns big-endian)
        bytes.extend_from_slice(&self.ciaddr.octets());
        bytes.extend_from_slice(&self.yiaddr.octets());
        bytes.extend_from_slice(&self.siaddr.octets());
        bytes.extend_from_slice(&self.giaddr.octets());
        
        // Write chaddr (16 bytes)
        bytes.extend_from_slice(&self.chaddr);
        
        // Write sname (64 bytes)
        bytes.extend_from_slice(&self.sname);
        
        // Write file (128 bytes)
        bytes.extend_from_slice(&self.file);
        
        // Write options (312 bytes)
        bytes.extend_from_slice(&self.options);

        bytes
    }
}

impl Default for DhcpPacket {
    /// Returns a zero-initialized `DhcpPacket`.
    ///
    /// Equivalent to `DhcpPacket::new()`.
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DhcpPacket {
    /// Formats `DhcpPacket` for debug output with all field values.
    ///
    /// Provides human-readable representation of packet contents for logging
    /// and debugging purposes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhcpPacket")
            .field("op", &self.op)
            .field("htype", &self.htype)
            .field("hlen", &self.hlen)
            .field("hops", &self.hops)
            .field("xid", &format_args!("0x{:08x}", self.xid))
            .field("secs", &self.secs)
            .field("flags", &format_args!("0x{:04x}", self.flags))
            .field("ciaddr", &self.ciaddr)
            .field("yiaddr", &self.yiaddr)
            .field("siaddr", &self.siaddr)
            .field("giaddr", &self.giaddr)
            .field("chaddr", &format_args!("{:02x?}", &self.chaddr[..self.hlen as usize]))
            .field("sname", &String::from_utf8_lossy(&self.sname))
            .field("file", &String::from_utf8_lossy(&self.file))
            .field("options", &format_args!("[{} bytes]", self.options.len()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversions() {
        assert_eq!(MessageType::DHCPDISCOVER.to_u8(), 1);
        assert_eq!(MessageType::DHCPOFFER.to_u8(), 2);
        assert_eq!(MessageType::from_u8(1), Some(MessageType::DHCPDISCOVER));
        assert_eq!(MessageType::from_u8(8), Some(MessageType::DHCPINFORM));
        assert_eq!(MessageType::from_u8(99), None);
    }

    #[test]
    fn test_option_code_conversions() {
        assert_eq!(OptionCode::OPTION_MESSAGE_TYPE.to_u8(), 53);
        assert_eq!(OptionCode::OPTION_END.to_u8(), 255);
        assert_eq!(OptionCode::from_u8(53), Some(OptionCode::OPTION_MESSAGE_TYPE));
        assert_eq!(OptionCode::from_u8(255), Some(OptionCode::OPTION_END));
        assert_eq!(OptionCode::from_u8(200), None);
    }

    #[test]
    fn test_dhcp_packet_new() {
        let packet = DhcpPacket::new();
        assert_eq!(packet.op, 0);
        assert_eq!(packet.xid, 0);
        assert_eq!(packet.ciaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(packet.chaddr, [0u8; 16]);
    }

    #[test]
    fn test_dhcp_packet_serialization() {
        let mut packet = DhcpPacket::new();
        packet.op = BOOTREQUEST;
        packet.htype = 1;
        packet.hlen = 6;
        packet.xid = 0x1234_5678;
        packet.ciaddr = Ipv4Addr::new(192, 168, 1, 100);

        let bytes = packet.to_bytes();
        assert_eq!(bytes.len(), 548);
        assert_eq!(bytes[0], BOOTREQUEST);
        assert_eq!(bytes[1], 1);
        assert_eq!(bytes[2], 6);
        
        // Verify xid in network byte order
        assert_eq!(&bytes[4..8], &[0x12, 0x34, 0x56, 0x78]);
        
        // Verify ciaddr in network byte order
        assert_eq!(&bytes[12..16], &[192, 168, 1, 100]);
    }

    #[test]
    fn test_dhcp_packet_deserialization() {
        let mut bytes = vec![0u8; 548];
        bytes[0] = BOOTREPLY;
        bytes[1] = 1; // htype
        bytes[2] = 6; // hlen
        bytes[4..8].copy_from_slice(&0x8765_4321_u32.to_be_bytes());
        bytes[16..20].copy_from_slice(&[192, 168, 1, 50]);

        let packet = DhcpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(packet.op, BOOTREPLY);
        assert_eq!(packet.htype, 1);
        assert_eq!(packet.hlen, 6);
        assert_eq!(packet.xid, 0x8765_4321);
        assert_eq!(packet.yiaddr, Ipv4Addr::new(192, 168, 1, 50));
    }

    #[test]
    fn test_dhcp_packet_roundtrip() {
        let mut original = DhcpPacket::new();
        original.op = BOOTREQUEST;
        original.xid = 0xAABB_CCDD;
        original.ciaddr = Ipv4Addr::new(10, 0, 0, 1);
        original.chaddr[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let bytes = original.to_bytes();
        let deserialized = DhcpPacket::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.op, original.op);
        assert_eq!(deserialized.xid, original.xid);
        assert_eq!(deserialized.ciaddr, original.ciaddr);
        assert_eq!(deserialized.chaddr, original.chaddr);
    }

    #[test]
    fn test_packet_too_short() {
        let bytes = vec![0u8; 100];
        let result = DhcpPacket::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(DHCP_SERVER_PORT, 67);
        assert_eq!(DHCP_CLIENT_PORT, 68);
        assert_eq!(PXE_PORT, 4011);
        assert_eq!(DHCP_COOKIE, 0x6382_5363);
        assert_eq!(MIN_PACKETSZ, 300);
        assert_eq!(BOOTREQUEST, 1);
        assert_eq!(BOOTREPLY, 2);
        assert_eq!(DHCP_CHADDR_MAX, 16);
    }

    #[test]
    fn test_suboption_code_conversions() {
        assert_eq!(SuboptionCode::SUBOPT_CIRCUIT_ID.to_u8(), 1);
        assert_eq!(SuboptionCode::from_u8(1), Some(SuboptionCode::SUBOPT_CIRCUIT_ID));
        assert_eq!(SuboptionCode::from_u8(99), None);
    }

    #[test]
    fn test_pxe_suboption_conversions() {
        assert_eq!(PxeSuboption::SUBOPT_PXE_BOOT_ITEM.to_u8(), 71);
        assert_eq!(PxeSuboption::from_u8(71), Some(PxeSuboption::SUBOPT_PXE_BOOT_ITEM));
        assert_eq!(PxeSuboption::from_u8(99), None);
    }
}
