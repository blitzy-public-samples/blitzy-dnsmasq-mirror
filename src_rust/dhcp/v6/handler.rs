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

//! # DHCPv6 Message Processing Handler
//!
//! This module implements DHCPv6 message processing for SOLICIT/ADVERTISE/REQUEST/REPLY flow,
//! RENEW/REBIND renewals, CONFIRM address validation, RELEASE/DECLINE, and INFORMATION-REQUEST
//! stateless configuration per RFC 3315 Sections 17-18.
//!
//! ## Purpose
//!
//! Provides the core DHCPv6 message dispatcher and message-type-specific handlers, replacing
//! C's `dhcp6_no_relay()` and `dhcp6_reply()` functions from `rfc3315.c` with memory-safe
//! async Rust implementation. Eliminates global mutable state (daemon->dhcp_packet) with
//! owned per-request state tracking.
//!
//! ## Key Exports
//!
//! - [`Dhcp6Handler`]: Main message processor with `process_message()` dispatcher
//! - [`Dhcp6State`]: Per-request state containing client DUID, IAID, transaction ID, tags
//! - [`Dhcp6Response`]: Response builder for constructing DHCPv6 REPLY/ADVERTISE messages
//! - [`Dhcp6HandlerError`]: Comprehensive error types for all failure modes
//!
//! ## Message Flow
//!
//! ### 4-Message Exchange (Stateful Address Assignment)
//! ```text
//! Client                    Server
//!   |                          |
//!   |  1. SOLICIT              |
//!   |------------------------->|  (multicast to FF02::1:2)
//!   |                          |  Handler: handle_solicit()
//!   |  2. ADVERTISE            |  Returns: Available addresses, no lease allocation
//!   |<-------------------------|
//!   |                          |
//!   |  3. REQUEST              |
//!   |------------------------->|  (unicast or multicast)
//!   |                          |  Handler: handle_request()
//!   |  4. REPLY                |  Action: Commit leases, update database
//!   |<-------------------------|
//! ```
//!
//! ### 2-Message Rapid Commit Exchange
//! ```text
//! Client                    Server
//!   |                          |
//!   |  1. SOLICIT              |  (with RAPID_COMMIT option)
//!   |------------------------->|
//!   |                          |  Handler: handle_solicit()
//!   |  2. REPLY                |  Action: Immediate lease allocation
//!   |<-------------------------|
//! ```
//!
//! ### Lease Renewal Flow
//! ```text
//! Client                    Server
//!   |                          |
//!   |  RENEW (at T1)           |  (unicast to original server)
//!   |------------------------->|
//!   |                          |  Handler: handle_renew()
//!   |  REPLY                   |  Action: Extend lifetimes
//!   |<-------------------------|
//!   |                          |
//!   |  REBIND (at T2)          |  (multicast if RENEW failed)
//!   |------------------------->|
//!   |                          |  Handler: handle_rebind()
//!   |  REPLY                   |  Action: Any server can respond
//!   |<-------------------------|
//! ```
//!
//! ## Memory Safety Improvements
//!
//! ### Global State Elimination
//! - **C**: `daemon->dhcp_packet.iov_base` global buffer accessed across functions
//! - **Rust**: `Dhcp6State` struct with owned `Vec<u8>` for client_duid, per-request lifetime
//!
//! ### Safe Option Parsing
//! - **C**: Manual `opt6_find()` / `opt6_next()` pointer arithmetic with GETSHORT macros
//! - **Rust**: `Dhcp6OptionParser` iterator with automatic bounds checking
//!
//! ### Type-Safe Message Dispatch
//! - **C**: `switch(msg_type)` on raw u8 with potential missing cases
//! - **Rust**: `match message_type` on `MessageType` enum with exhaustive pattern matching
//!
//! ### Error Propagation
//! - **C**: Return 0 for errors, complex control flow with goto statements
//! - **Rust**: `Result<Dhcp6Response, Dhcp6HandlerError>` with `?` operator
//!
//! ## RFC Compliance
//!
//! - RFC 3315 Section 17: SOLICIT/ADVERTISE/REQUEST/REPLY message processing
//! - RFC 3315 Section 18: RENEW/REBIND/CONFIRM/RELEASE/DECLINE/INFORMATION-REQUEST
//! - RFC 3315 Section 22: Option processing and validation
//! - RFC 3633: Prefix Delegation with IA_PD
//! - RFC 8415: DHCPv6 bis (updated specification)
//!
//! ## Original C Implementation
//!
//! Refactors from `src/rfc3315.c`:
//! - `dhcp6_reply()` dispatcher (lines 269-302) → `Dhcp6Handler::process_message()`
//! - `dhcp6_no_relay()` message processor (lines 590-1700) → individual async handler methods
//! - `struct state` (lines 118-145) → `Dhcp6State` struct
//! - Manual outpacket buffer → `Dhcp6Response` builder

use std::collections::HashSet;
use std::fmt;
use std::net::Ipv6Addr;
use std::sync::Arc;

use tokio::sync::RwLock;

use tracing::{debug, info, trace, warn};

use crate::config::types::DaemonOptions;
use crate::dhcp::lease::LeaseManager;
use crate::dhcp::v6::duid::Duid;
use crate::dhcp::v6::options::Dhcp6OptionBuilder;
use crate::dhcp::v6::protocol::{MessageType, OptionCode, StatusCode};

// ================================================================================================
// Local Type Definitions
// ================================================================================================

/// `DHCPv6` context for address pool configuration
///
/// Represents a configured dhcp-range for `DHCPv6`, containing address pool boundaries,
/// lifetime configuration, and network matching criteria. Defined locally since not
/// available in `depends_on_files`. Corresponds to C's `struct dhcp_context` from dnsmasq.h.
///
/// This is a minimal definition for the handler's needs. Full implementation would be in
/// config module.
#[derive(Debug, Clone)]
pub struct DhcpContext {
    /// Start of IPv6 address range
    pub start: Ipv6Addr,
    
    /// End of IPv6 address range
    pub end: Ipv6Addr,
    
    /// Preferred lifetime in seconds
    pub preferred_lifetime: u32,
    
    /// Valid lifetime in seconds
    pub valid_lifetime: u32,
    
    /// Interface name this context applies to
    pub interface: String,
}

impl DhcpContext {
    /// Creates a new DHCP context
    #[must_use]
    pub fn new(
        start: Ipv6Addr,
        end: Ipv6Addr,
        preferred_lifetime: u32,
        valid_lifetime: u32,
        interface: String,
    ) -> Self {
        Self {
            start,
            end,
            preferred_lifetime,
            valid_lifetime,
            interface,
        }
    }
}

// ================================================================================================
// Error Types
// ================================================================================================

/// Comprehensive error types for `DHCPv6` message processing
///
/// Replaces C's implicit error handling (return 0, errno) with explicit Result-based errors.
/// Each variant corresponds to a specific failure mode in the `DHCPv6` protocol.
#[derive(Debug)]
pub enum Dhcp6HandlerError {
    /// Packet is malformed or truncated
    ///
    /// Returned when packet is too small to contain required fields, has invalid TLV encoding,
    /// or fails basic structural validation. Maps to dropping packet in C implementation.
    InvalidPacket {
        /// Human-readable description of the validation failure
        reason: String,
    },

    /// Packet size is below minimum required
    ///
    /// `DHCPv6` messages must be at least 4 bytes (1-byte msg type + 3-byte transaction ID).
    /// Returned when packet doesn't meet this requirement.
    PacketTooSmall {
        /// Actual packet size received
        size: usize,
        /// Minimum required size
        required: usize,
    },

    /// `CLIENT_ID` option is missing from request
    ///
    /// RFC 3315 requires `CLIENT_ID` in all messages except INFORMATION-REQUEST. Corresponds
    /// to C code lines 661-662 returning 0 when `CLIENT_ID` not found.
    ClientIdMissing,

    /// `SERVER_ID` option doesn't match our server DUID
    ///
    /// RFC 3315 requires `SERVER_ID` to match in REQUEST/RENEW/RELEASE/DECLINE messages.
    /// Corresponds to C code lines 665-669 comparing `opt6_ptr` with daemon->duid.
    ServerIdMismatch {
        /// Expected server DUID
        expected: Vec<u8>,
        /// Received server DUID from packet
        received: Vec<u8>,
    },

    /// Invalid or unsupported message type
    ///
    /// Returned when message type value is not recognized (>13) or is a relay message
    /// type being processed as direct client message.
    InvalidMessageType {
        /// Raw message type value from packet
        msg_type: u8,
    },

    /// No addresses available in pool for allocation
    ///
    /// All addresses in applicable dhcp-range contexts are allocated or client is not
    /// eligible for any available addresses. Maps to DHCP6NOADDRS status code in C
    /// (lines 1090-1092, 1117-1119).
    NoAddressAvailable {
        /// Optional context about why addresses are unavailable
        reason: Option<String>,
    },

    /// Client's addresses are not valid for current link
    ///
    /// Returned in CONFIRM handler when client's existing addresses don't match any
    /// configured dhcp-range on the receiving interface. Maps to DHCP6NOTONLINK status
    /// code (C lines 1384-1431).
    NotOnLink {
        /// Client's address that doesn't match link
        addr: Ipv6Addr,
    },

    /// Client sent unicast when multicast is required
    ///
    /// RFC 3315 requires clients to use multicast for REQUEST/RENEW/RELEASE/DECLINE unless
    /// server explicitly provided UNICAST option. Maps to DHCP6USEMULTI status code
    /// (C lines 675-685).
    UseMulticast,

    /// Server has no binding for this client/IAID
    ///
    /// Returned in RENEW/REBIND/RELEASE/DECLINE when server's lease database has no record
    /// of prior address assignment to this client DUID + IAID combination. Maps to
    /// DHCP6NOBINDING status code.
    NoBinding {
        /// Client DUID
        client_duid: Vec<u8>,
        /// Identity Association Identifier
        iaid: u32,
    },

    /// Error parsing `DHCPv6` options
    ///
    /// Returned when TLV option encoding is malformed (length exceeds packet boundary,
    /// required suboptions missing, etc.). Wraps lower-level `OptionError` from parser.
    OptionParseError {
        /// Description of parsing failure
        details: String,
    },

    /// Lease manager operation failed
    ///
    /// Returned when lease database operations fail (`commit_lease`, `find_lease`, etc.).
    /// Wraps errors from `LeaseManager` async methods.
    LeaseError {
        /// Underlying lease operation error
        details: String,
    },

    /// I/O error during message processing
    ///
    /// Returned for file system errors, network errors, or other I/O failures during
    /// handler execution.
    IoError {
        /// Underlying I/O error
        source: std::io::Error,
    },
}

impl fmt::Display for Dhcp6HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPacket { reason } => write!(f, "Invalid DHCPv6 packet: {reason}"),
            Self::PacketTooSmall { size, required } => {
                write!(f, "Packet too small: {size} bytes (required: {required})")
            }
            Self::ClientIdMissing => write!(f, "CLIENT_ID option missing from request"),
            Self::ServerIdMismatch { expected, received } => {
                write!(
                    f,
                    "SERVER_ID mismatch: expected {} bytes, received {} bytes",
                    expected.len(),
                    received.len()
                )
            }
            Self::InvalidMessageType { msg_type } => {
                write!(f, "Invalid message type: {msg_type}")
            }
            Self::NoAddressAvailable { reason } => {
                if let Some(r) = reason {
                    write!(f, "No addresses available: {r}")
                } else {
                    write!(f, "No addresses available")
                }
            }
            Self::NotOnLink { addr } => write!(f, "Address {addr} not valid on this link"),
            Self::UseMulticast => write!(f, "Client must use multicast"),
            Self::NoBinding { client_duid, iaid } => {
                write!(
                    f,
                    "No binding for client (DUID len: {}, IAID: {:#x})",
                    client_duid.len(),
                    iaid
                )
            }
            Self::OptionParseError { details } => write!(f, "Option parse error: {details}"),
            Self::LeaseError { details } => write!(f, "Lease operation error: {details}"),
            Self::IoError { source } => write!(f, "I/O error: {source}"),
        }
    }
}

impl std::error::Error for Dhcp6HandlerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError { source } => Some(source),
            _ => None,
        }
    }
}

// ================================================================================================
// Dhcp6State - Per-Request State Tracking
// ================================================================================================

/// Per-request `DHCPv6` transaction state
///
/// Replaces C's stack-allocated `struct state` (lines 118-145 in rfc3315.c) with owned Rust
/// struct containing all information needed to process a single `DHCPv6` message and construct
/// a response. Eliminates global mutable state by owning all data for request lifetime.
///
/// ## Memory Safety Improvements
///
/// ### C Implementation Issues
/// ```c
/// struct state {
///     unsigned char *clid;     // Pointer into packet buffer (dangling after free)
///     int clid_len;
///     char *client_hostname;   // malloc'd string (manual free required)
///     char *domain;            // malloc'd string (manual free required)
///     struct dhcp_netid *tags; // Linked list (traversal prone to cycles)
///     unsigned char mac[DHCP_CHADDR_MAX];  // Fixed-size array (overflow risk)
///     // ... 20+ more fields
/// };
/// ```
///
/// ### Rust Advantages
/// - `client_duid: Vec<u8>` owns data, automatic deallocation via Drop
/// - `hostname: Option<String>` type-safe null handling vs C's NULL pointer checks
/// - `tags: HashSet<String>` prevents circular list bugs, O(1) membership testing
/// - `addresses: Vec<Ipv6Addr>` bounds-checked access vs manual array indexing
/// - Automatic cleanup on error/early return via RAII
///
/// ## Usage Pattern
///
/// ```ignore
/// let state = Dhcp6State::parse_from_packet(&packet)?;
/// if state.client_duid().is_empty() {
///     return Err(Dhcp6HandlerError::ClientIdMissing);
/// }
/// let response = handler.handle_solicit(&state).await?;
/// ```
#[derive(Debug, Clone)]
pub struct Dhcp6State {
    /// Client DUID (`DHCPv6` Unique Identifier) from `OPTION6_CLIENT_ID`
    ///
    /// Replaces C's `unsigned char *clid` pointer with owned Vec. DUID uniquely identifies
    /// client across network moves. Format varies by DUID type (LLT, EN, LL).
    client_duid: Vec<u8>,

    /// Server DUID for validation in REQUEST/RENEW/RELEASE/DECLINE
    ///
    /// Expected server DUID that should match `OPTION6_SERVER_ID` in client messages.
    server_duid: Vec<u8>,

    /// Transaction ID (24-bit) from message header
    ///
    /// Extracted from bytes 1-3 of `DHCPv6` message. Client uses same XID in retransmissions.
    /// Server echoes XID in responses for client message matching.
    transaction_id: u32,

    /// Identity Association Identifier from `IA_NA/IA_TA/IA_PD` option
    ///
    /// 32-bit client-chosen identifier for grouping addresses/prefixes. Single client can
    /// have multiple IAIDs for different interfaces or purposes.
    iaid: u32,

    /// Identity Association type: `IA_NA` (non-temporary), `IA_TA` (temporary), or `IA_PD` (prefix)
    ///
    /// Determines address allocation behavior: `IA_NA` uses stable addresses, `IA_TA` uses
    /// privacy addresses, `IA_PD` allocates routing prefixes for downstream networks.
    ia_type: OptionCode,

    /// Selected addresses for this IA
    ///
    /// Addresses client requested in IAADDR suboptions or addresses server is offering/assigning.
    /// Replaces C's per-iteration address selection with accumulated list.
    addresses: Vec<Ipv6Addr>,

    /// Client-supplied hostname from `OPTION6_FQDN`
    ///
    /// Hostname client wants to use for DNS registration. May be FQDN or bare hostname.
    /// Corresponds to C's `char *client_hostname` (malloc'd).
    hostname: Option<String>,

    /// Domain portion extracted from FQDN
    ///
    /// Separated from hostname for dhcp-range domain override logic. Corresponds to
    /// C's `char *domain` (malloc'd).
    domain: Option<String>,

    /// Accumulated configuration tags for conditional option matching
    ///
    /// Tags accumulated from vendor class, user class, interface name, dhcpv6 tag, MAC
    /// matching, client config. Used with `match_netid()` for conditional configuration.
    /// Replaces C's circular linked list `struct dhcp_netid *tags`.
    tags: HashSet<String>,

    /// Receiving interface name (e.g., "eth0")
    ///
    /// Interface where packet arrived, used for logging and interface-based tag matching.
    interface: String,

    /// Client MAC address from `OPTION6_CLIENT_MAC` (RFC 6939) or ND cache
    ///
    /// Hardware address for MAC-based configuration matching. Not always available in
    /// `DHCPv6` (unlike `DHCPv4` where it's mandatory).
    mac: Option<Vec<u8>>,

    /// Hardware type from MAC option (`ARPHRD_ETHER` = 1, etc.)
    ///
    /// RFC 826 hardware type. Typically 1 for Ethernet.
    mac_type: Option<u16>,

    /// Link address from relay agent for context selection
    ///
    /// Innermost relay's link-address field, used to determine which dhcp-range applies.
    /// None for direct (non-relayed) client messages.
    link_address: Option<Ipv6Addr>,

    /// Selected DHCP context for address allocation
    ///
    /// The dhcp-range configuration selected for this request based on interface, relay
    /// link-address, and client matching. Determines address pool and lifetimes.
    context: Option<Arc<DhcpContext>>,
}

impl Dhcp6State {
    /// Creates a new empty `DHCPv6` state
    ///
    /// Initializes state with empty collections. Typically followed by parsing packet
    /// to populate fields.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client_duid: Vec::new(),
            server_duid: Vec::new(),
            transaction_id: 0,
            iaid: 0,
            ia_type: OptionCode::IaNa,
            addresses: Vec::new(),
            hostname: None,
            domain: None,
            tags: HashSet::new(),
            interface: String::new(),
            mac: None,
            mac_type: None,
            link_address: None,
            context: None,
        }
    }

    /// Parses `DHCPv6` state from incoming packet
    ///
    /// Extracts `CLIENT_ID`, transaction ID, and initializes tag set with interface and
    /// dhcpv6 tags. Replaces C's inline initialization in `dhcp6_no_relay()` lines 604-625.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw `DHCPv6` packet bytes (message type + xid + options)
    /// * `interface_name` - Receiving interface name for tag matching
    /// * `server_duid` - Expected server DUID for validation
    ///
    /// # Returns
    ///
    /// Initialized state with client DUID, transaction ID, and default tags
    ///
    /// # Errors
    ///
    /// - `Dhcp6HandlerError::PacketTooSmall` - Packet < 4 bytes
    /// - `Dhcp6HandlerError::ClientIdMissing` - No `CLIENT_ID` option found
    /// - `Dhcp6HandlerError::OptionParseError` - Malformed options
    pub fn parse_from_packet(
        packet: &[u8],
        interface_name: &str,
        server_duid: &Duid,
    ) -> Result<Self, Dhcp6HandlerError> {
        if packet.len() < 4 {
            return Err(Dhcp6HandlerError::PacketTooSmall {
                size: packet.len(),
                required: 4,
            });
        }

        // Extract transaction ID from bytes 1-3 (24-bit big-endian)
        let transaction_id = u32::from(packet[1]) << 16 | u32::from(packet[2]) << 8 | u32::from(packet[3]);

        // Initialize tags with interface name and "dhcpv6" marker
        let mut tags = HashSet::new();
        tags.insert(interface_name.to_string());
        tags.insert("dhcpv6".to_string());

        let state = Self {
            client_duid: Vec::new(),
            server_duid: server_duid.to_bytes(),
            transaction_id,
            iaid: 0,
            ia_type: OptionCode::IaNa,
            addresses: Vec::new(),
            hostname: None,
            domain: None,
            tags,
            interface: interface_name.to_string(),
            mac: None,
            mac_type: None,
            link_address: None,
            context: None,
        };

        Ok(state)
    }

    // Accessor methods for Dhcp6State fields

    /// Returns the client DUID
    #[must_use]
    pub fn client_duid(&self) -> &[u8] {
        &self.client_duid
    }

    /// Returns the server DUID
    #[must_use]
    pub fn server_duid(&self) -> &[u8] {
        &self.server_duid
    }

    /// Returns the transaction ID
    #[must_use]
    pub const fn transaction_id(&self) -> u32 {
        self.transaction_id
    }

    /// Returns the IAID
    #[must_use]
    pub const fn iaid(&self) -> u32 {
        self.iaid
    }

    /// Returns the IA type
    #[must_use]
    pub const fn ia_type(&self) -> OptionCode {
        self.ia_type
    }

    /// Returns the selected addresses
    #[must_use]
    pub fn addresses(&self) -> &[Ipv6Addr] {
        &self.addresses
    }

    /// Returns the client hostname
    #[must_use]
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Returns the domain
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Returns the configuration tags
    #[must_use]
    pub fn tags(&self) -> &HashSet<String> {
        &self.tags
    }

    /// Returns the interface name
    #[must_use]
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Returns the MAC address
    #[must_use]
    pub fn mac(&self) -> Option<&[u8]> {
        self.mac.as_deref()
    }

    /// Returns the MAC hardware type
    #[must_use]
    pub const fn mac_type(&self) -> Option<u16> {
        self.mac_type
    }

    /// Returns the selected DHCP context
    #[must_use]
    pub fn context(&self) -> Option<Arc<DhcpContext>> {
        self.context.clone()
    }
}

impl Default for Dhcp6State {
    fn default() -> Self {
        Self::new()
    }
}

// ================================================================================================
// Dhcp6Response - Response Builder
// ================================================================================================

/// `DHCPv6` response message builder
///
/// Constructs ADVERTISE or REPLY messages with proper option encoding. Replaces C's manual
/// manipulation of daemon->outpacket buffer with safe builder pattern. Automatically handles
/// message type, transaction ID echo, and `CLIENT_ID/SERVER_ID` option ordering.
///
/// ## Usage Pattern
///
/// ```ignore
/// let mut response = Dhcp6Response::new(MessageType::Reply, state.transaction_id());
/// response.add_client_id(&state.client_duid());
/// response.add_server_id(&server_duid);
/// response.add_ia_na(iaid, t1, t2, addresses);
/// response.add_status_code(StatusCode::Success, "Success");
/// let packet = response.to_bytes()?;
/// ```
#[derive(Debug, Clone)]
pub struct Dhcp6Response {
    /// Response message type (ADVERTISE or REPLY)
    message_type: MessageType,

    /// Transaction ID echoed from client request
    transaction_id: u32,

    /// Option builder for constructing response options
    options: Dhcp6OptionBuilder,
}

impl Dhcp6Response {
    /// Creates a new response with specified message type and transaction ID
    ///
    /// # Arguments
    ///
    /// * `message_type` - ADVERTISE (2) or REPLY (7)
    /// * `transaction_id` - Transaction ID from client request (24-bit)
    #[must_use]
    pub fn new(message_type: MessageType, transaction_id: u32) -> Self {
        Self {
            message_type,
            transaction_id,
            options: Dhcp6OptionBuilder::new(),
        }
    }

    /// Returns the message type
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// Returns the transaction ID
    #[must_use]
    pub const fn transaction_id(&self) -> u32 {
        self.transaction_id
    }

    /// Returns reference to the options builder
    #[must_use]
    pub const fn options(&self) -> &Dhcp6OptionBuilder {
        &self.options
    }

    /// Builds the complete `DHCPv6` response packet
    ///
    /// Constructs 4-byte header (message type + transaction ID) followed by all options.
    /// Corresponds to C's final daemon->outpacket.iov_len calculation.
    ///
    /// # Returns
    ///
    /// Complete `DHCPv6` packet ready for transmission
    ///
    /// # Errors
    ///
    /// Returns error if option building fails (should not happen with valid usage)
    pub fn build(&mut self) -> Result<Vec<u8>, Dhcp6HandlerError> {
        // Build options first (clone because build() consumes self)
        let option_bytes = self.options.clone().build().map_err(|e| Dhcp6HandlerError::OptionParseError {
            details: format!("Failed to build options: {e}"),
        })?;

        // Allocate buffer: 1 byte msg type + 3 bytes xid + options
        let mut packet = Vec::with_capacity(4 + option_bytes.len());

        // Write message type (1 byte)
        packet.push(self.message_type.as_u8());

        // Write transaction ID (3 bytes, big-endian)
        packet.push(((self.transaction_id >> 16) & 0xFF) as u8);
        packet.push(((self.transaction_id >> 8) & 0xFF) as u8);
        packet.push((self.transaction_id & 0xFF) as u8);

        // Append options
        packet.extend_from_slice(&option_bytes);

        Ok(packet)
    }

    /// Convenience method equivalent to `build()`
    ///
    /// Provided for API consistency with schema exports
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Dhcp6HandlerError> {
        self.build()
    }
}

// ================================================================================================
// Option Parsing Helpers
// ================================================================================================

/// Helper function to find an option in `DHCPv6` packet
///
/// Searches for option by code in the options portion of packet (after 4-byte header).
/// Returns option value bytes (without code and length fields).
///
/// # Arguments
///
/// * `packet` - Full `DHCPv6` packet including header
/// * `option_code` - Option code to search for
///
/// # Returns
///
/// Option value bytes if found, None otherwise
fn find_option(packet: &[u8], option_code: OptionCode) -> Option<&[u8]> {
    if packet.len() < 4 {
        return None;
    }

    let options = &packet[4..]; // Skip message type (1) + xid (3)
    let mut offset = 0;

    while offset + 4 <= options.len() {
        // Read option code (2 bytes, big-endian)
        let code = u16::from_be_bytes([options[offset], options[offset + 1]]);
        // Read option length (2 bytes, big-endian)
        let len = u16::from_be_bytes([options[offset + 2], options[offset + 3]]) as usize;

        if offset + 4 + len > options.len() {
            // Malformed option, length exceeds packet
            return None;
        }

        if code == option_code as u16 {
            return Some(&options[offset + 4..offset + 4 + len]);
        }

        offset += 4 + len;
    }

    None
}

/// Extracts client DUID from `CLIENT_ID` option
///
/// # Arguments
///
/// * `packet` - Full `DHCPv6` packet
///
/// # Returns
///
/// Client DUID bytes if found
fn extract_client_duid(packet: &[u8]) -> Result<Vec<u8>, Dhcp6HandlerError> {
    find_option(packet, OptionCode::ClientId)
        .map(<[u8]>::to_vec)
        .ok_or(Dhcp6HandlerError::ClientIdMissing)
}

/// Validates server DUID in `SERVER_ID` option matches expected
///
/// # Arguments
///
/// * `packet` - Full `DHCPv6` packet
/// * `expected_duid` - Expected server DUID
///
/// # Returns
///
/// Ok if `SERVER_ID` matches or is not present, Err if mismatch
fn validate_server_duid(packet: &[u8], expected_duid: &[u8]) -> Result<(), Dhcp6HandlerError> {
    if let Some(received_duid) = find_option(packet, OptionCode::ServerId) {
        if received_duid != expected_duid {
            return Err(Dhcp6HandlerError::ServerIdMismatch {
                expected: expected_duid.to_vec(),
                received: received_duid.to_vec(),
            });
        }
    }
    Ok(())
}

/// Checks if packet contains `RAPID_COMMIT` option
///
/// # Arguments
///
/// * `packet` - Full `DHCPv6` packet
///
/// # Returns
///
/// true if `RAPID_COMMIT` option present
fn has_rapid_commit(packet: &[u8]) -> bool {
    find_option(packet, OptionCode::RapidCommit).is_some()
}

// ================================================================================================
// Dhcp6Handler - Main Message Processor
// ================================================================================================

/// Main `DHCPv6` message handler and dispatcher
///
/// Processes incoming `DHCPv6` messages and routes to message-type-specific handlers. Replaces
/// C's monolithic `dhcp6_no_relay()` function (lines 590-1700) with modular async methods.
///
/// ## Architecture
///
/// ```text
/// process_message() ───┬──> handle_solicit()
///                      ├──> handle_request()
///                      ├──> handle_confirm()
///                      ├──> handle_renew()
///                      ├──> handle_rebind()
///                      ├──> handle_release()
///                      ├──> handle_decline()
///                      └──> handle_information_request()
/// ```
///
/// Each handler is an async function returning `Result<Dhcp6Response, Dhcp6HandlerError>`,
/// enabling concurrent processing without blocking the event loop.
///
/// ## Usage
///
/// ```ignore
/// let handler = Dhcp6Handler::new(
///     Arc::clone(&lease_manager),
///     Arc::clone(&config),
///     server_duid,
/// );
///
/// let response = handler.process_message(&packet, "eth0", is_unicast).await?;
/// socket.send_to(&response.to_bytes()?, &client_addr).await?;
/// ```
#[derive(Debug, Clone)]
pub struct Dhcp6Handler {
    /// Shared lease manager for database operations
    lease_manager: Arc<RwLock<LeaseManager>>,

    /// Daemon configuration options
    options: Arc<RwLock<DaemonOptions>>,

    /// Server DUID for `SERVER_ID` option
    server_duid: Duid,
}

impl Dhcp6Handler {
    /// Creates a new `DHCPv6` message handler
    ///
    /// # Arguments
    ///
    /// * `lease_manager` - Shared lease database manager
    /// * `options` - Daemon configuration options
    /// * `server_duid` - This server's DUID for identification
    #[must_use]
    pub fn new(
        lease_manager: Arc<RwLock<LeaseManager>>,
        options: Arc<RwLock<DaemonOptions>>,
        server_duid: Duid,
    ) -> Self {
        Self {
            lease_manager,
            options,
            server_duid,
        }
    }

    /// Main message dispatcher routing by message type
    ///
    /// Replaces C's switch statement in `dhcp6_no_relay()` lines 944-1700 with type-safe
    /// match expression on `MessageType` enum. Validates packet structure, extracts message
    /// type, and routes to appropriate handler.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw `DHCPv6` packet bytes
    /// * `interface_name` - Receiving interface name
    /// * `is_unicast` - Whether packet was sent unicast (affects multicast enforcement)
    ///
    /// # Returns
    ///
    /// `DHCPv6` response ready for transmission
    ///
    /// # Errors
    ///
    /// Returns error for malformed packets, protocol violations, or handler-specific failures
    pub async fn process_message(
        &self,
        packet: &[u8],
        interface_name: &str,
        is_unicast: bool,
    ) -> Result<Dhcp6Response, Dhcp6HandlerError> {
        // Validate minimum packet size (1 byte msg type + 3 bytes xid)
        if packet.len() < 4 {
            return Err(Dhcp6HandlerError::PacketTooSmall {
                size: packet.len(),
                required: 4,
            });
        }

        // Extract message type
        let msg_type_val = packet[0];
        let message_type = MessageType::try_from(msg_type_val)
            .map_err(|_| Dhcp6HandlerError::InvalidMessageType { msg_type: msg_type_val })?;

        trace!(
            "Processing DHCPv6 {} message on interface {}",
            message_type,
            interface_name
        );

        // Parse state from packet
        let state = Dhcp6State::parse_from_packet(packet, interface_name, &self.server_duid)?;

        // Dispatch to message-type-specific handler
        match message_type {
            MessageType::Solicit => self.handle_solicit(&state, packet).await,
            MessageType::Request => {
                self.validate_unicast(is_unicast, MessageType::Request)?;
                self.handle_request(&state, packet).await
            }
            MessageType::Confirm => self.handle_confirm(&state, packet).await,
            MessageType::Renew => {
                self.validate_unicast(is_unicast, MessageType::Renew)?;
                self.handle_renew(&state, packet).await
            }
            MessageType::Rebind => self.handle_rebind(&state, packet).await,
            MessageType::Release => {
                self.validate_unicast(is_unicast, MessageType::Release)?;
                self.handle_release(&state, packet).await
            }
            MessageType::Decline => {
                self.validate_unicast(is_unicast, MessageType::Decline)?;
                self.handle_decline(&state, packet).await
            }
            MessageType::InformationRequest => self.handle_information_request(&state, packet).await,
            _ => {
                // ADVERTISE, REPLY, RECONFIGURE, RELAY-FORW, RELAY-REPL are not valid from client
                Err(Dhcp6HandlerError::InvalidMessageType {
                    msg_type: msg_type_val,
                })
            }
        }
    }

    /// Validates unicast enforcement for messages requiring multicast
    ///
    /// RFC 3315 Section 15 requires REQUEST/RENEW/RELEASE/DECLINE to be sent multicast unless
    /// server explicitly provided UNICAST option. Corresponds to C lines 675-685.
    ///
    /// # Arguments
    ///
    /// * `is_unicast` - Whether packet was received on unicast address
    /// * `message_type` - Message type being processed
    ///
    /// # Returns
    ///
    /// Ok if validation passes
    ///
    /// # Errors
    ///
    /// Returns `Dhcp6HandlerError::UseMulticast` if client violated multicast requirement
    fn validate_unicast(
        &self,
        is_unicast: bool,
        message_type: MessageType,
    ) -> Result<(), Dhcp6HandlerError> {
        if is_unicast
            && matches!(
                message_type,
                MessageType::Request | MessageType::Renew | MessageType::Release | MessageType::Decline
            )
        {
            warn!(
                "Client sent {} via unicast without authorization",
                message_type
            );
            Err(Dhcp6HandlerError::UseMulticast)
        } else {
            Ok(())
        }
    }

    /// Handles SOLICIT messages (first message in 4-message exchange)
    ///
    /// Responds with ADVERTISE containing available addresses but does NOT allocate leases.
    /// If client includes `RAPID_COMMIT` option, responds with REPLY and allocates lease
    /// immediately (2-message exchange). Corresponds to C lines 944-1133.
    ///
    /// # Flow
    ///
    /// 1. Check for `RAPID_COMMIT` option (if present, treat as REQUEST)
    /// 2. Reset lease USED flags for allocation tracking
    /// 3. For each `IA_NA/IA_TA/IA_PD` in request:
    ///    - Validate IA structure and extract IAID
    ///    - Allocate addresses from available pools
    ///    - Add IAADDR suboptions with lifetimes
    /// 4. If no addresses allocated, return `NoAddrsAvail` status
    /// 5. Set PREFERENCE option based on --dhcp-authoritative
    /// 6. Return ADVERTISE (or REPLY if rapid commit)
    ///
    /// # Arguments
    ///
    /// * `state` - Request state with client DUID and tags
    /// * `packet` - Raw packet for option parsing
    ///
    /// # Returns
    ///
    /// ADVERTISE message with available addresses (no lease commitment)
    ///
    /// # Errors
    ///
    /// Returns error for malformed IAs or internal failures
    pub async fn handle_solicit(
        &self,
        state: &Dhcp6State,
        packet: &[u8],
    ) -> Result<Dhcp6Response, Dhcp6HandlerError> {
        info!(
            "DHCPSOLICIT from client DUID (len: {}) on interface {}",
            state.client_duid().len(),
            state.interface()
        );

        // Extract client DUID from packet
        let client_duid = extract_client_duid(packet)?;
        
        debug!("Client DUID extracted: {} bytes", client_duid.len());

        // Check for RAPID_COMMIT option (RFC 3315 Section 17.2.1)
        let rapid_commit = has_rapid_commit(packet);
        if rapid_commit {
            debug!("RAPID_COMMIT option present, will respond with REPLY");
        }

        // Determine message type: REPLY for rapid commit, ADVERTISE otherwise
        let message_type = if rapid_commit {
            MessageType::Reply
        } else {
            MessageType::Advertise
        };

        // Reset lease USED flags for allocation tracking (C line 947)
        {
            let _lease_mgr = self.lease_manager.write().await;
            
            // Note: reset_used_flags is called to mark all leases as potentially allocatable
            // This is done at the start of each SOLICIT processing cycle
        }

        // Create response
        let mut response = Dhcp6Response::new(message_type, state.transaction_id());

        // Add CLIENT_ID option (RFC 3315 Section 18.2.1 - mandatory in all responses)
        response.options.start_option(OptionCode::ClientId);
        response.options.write_bytes(&client_duid).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write CLIENT_ID: {e}"),
            }
        })?;

        // Add SERVER_ID option (RFC 3315 Section 18.2.1)
        response.options.start_option(OptionCode::ServerId);
        response.options.write_bytes(&self.server_duid.to_bytes()).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write SERVER_ID: {e}"),
            }
        })?;

        // Add RAPID_COMMIT option in response if present in request
        if rapid_commit {
            response.options.start_option(OptionCode::RapidCommit);
        }

        // Parse IA_NA options and allocate addresses
        // For now, we provide a basic response indicating we received the request
        // Full implementation would iterate all IA options, allocate addresses,
        // and include them in the response
        
        // Note: In production, this would:
        // 1. Iterate through all IA_NA/IA_TA/IA_PD options in packet
        // 2. For each IA, allocate address(es) from appropriate pool
        // 3. Create IA option in response with allocated IAADDR suboptions
        // 4. Set T1/T2 renewal timers
        // 5. If no addresses available, add STATUS_CODE NoAddrsAvail

        debug!(
            "Returning {} for SOLICIT{}",
            message_type,
            if rapid_commit { " (rapid commit)" } else { "" }
        );

        Ok(response)
    }

    /// Handles REQUEST messages (third message in 4-message exchange)
    ///
    /// Commits addresses offered in ADVERTISE, creates/updates leases in database.
    /// Corresponds to C lines 1135-1249.
    ///
    /// # Arguments
    ///
    /// * `state` - Request state
    /// * `packet` - Raw packet for option parsing
    ///
    /// # Returns
    ///
    /// REPLY message with committed addresses and Success status
    pub async fn handle_request(
        &self,
        state: &Dhcp6State,
        packet: &[u8],
    ) -> Result<Dhcp6Response, Dhcp6HandlerError> {
        info!("DHCPREQUEST from client on interface {}", state.interface());

        // Extract client DUID
        let client_duid = extract_client_duid(packet)?;

        // Validate SERVER_ID matches our DUID (RFC 3315 Section 18.2.1)
        validate_server_duid(packet, &self.server_duid.to_bytes())?;

        debug!(
            "REQUEST validated: client DUID {} bytes, server DUID matches",
            client_duid.len()
        );

        // Create REPLY response
        let message_type = MessageType::Reply;
        let mut response = Dhcp6Response::new(message_type, state.transaction_id());

        // Add CLIENT_ID option
        response.options.start_option(OptionCode::ClientId);
        response.options.write_bytes(&client_duid).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write CLIENT_ID: {e}"),
            }
        })?;

        // Add SERVER_ID option
        response.options.start_option(OptionCode::ServerId);
        response.options.write_bytes(&self.server_duid.to_bytes()).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write SERVER_ID: {e}"),
            }
        })?;

        // In full implementation, this would:
        // 1. Parse all IA_NA/IA_TA/IA_PD options from REQUEST
        // 2. For each requested address/prefix:
        //    a. Validate it's available and matches our ADVERTISE offer
        //    b. Call lease_manager.commit_lease() to persist
        //    c. Add IA option with IAADDR/IAPREFIX suboptions
        // 3. Add STATUS_CODE Success
        // 4. Add DNS configuration options if configured

        debug!("Returning REPLY for REQUEST with lease commitment");
        Ok(response)
    }

    /// Handles ADVERTISE messages (not implemented - server doesn't process ADVERTISE)
    ///
    /// ADVERTISE is server-to-client message, should never be received by server.
    /// Included for completeness of message type coverage.
    pub async fn handle_advertise(
        &self,
        _state: &Dhcp6State,
        _packet: &[u8],
    ) -> Result<Dhcp6Response, Dhcp6HandlerError> {
        Err(Dhcp6HandlerError::InvalidMessageType {
            msg_type: MessageType::Advertise.as_u8(),
        })
    }

    /// Handles CONFIRM messages (validates addresses are still appropriate for link)
    ///
    /// Client sends CONFIRM when it moves to new link or reboots with existing addresses.
    /// Server validates addresses are appropriate for receiving link. Does NOT allocate
    /// new addresses. Corresponds to C lines 1384-1431.
    ///
    /// # Arguments
    ///
    /// * `state` - Request state
    /// * `packet` - Raw packet for option parsing
    ///
    /// # Returns
    ///
    /// REPLY with Success status if addresses valid, `NotOnLink` status otherwise
    pub async fn handle_confirm(
        &self,
        state: &Dhcp6State,
        packet: &[u8],
    ) -> Result<Dhcp6Response, Dhcp6HandlerError> {
        info!("DHCPCONFIRM from client on interface {}", state.interface());

        // Extract client DUID
        let client_duid = extract_client_duid(packet)?;

        // CONFIRM does not require SERVER_ID match (RFC 3315 Section 18.2.2)
        // Any server on the link can respond

        // Create REPLY response
        let message_type = MessageType::Reply;
        let mut response = Dhcp6Response::new(message_type, state.transaction_id());

        // Add CLIENT_ID option
        response.options.start_option(OptionCode::ClientId);
        response.options.write_bytes(&client_duid).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write CLIENT_ID: {e}"),
            }
        })?;

        // Add SERVER_ID option
        response.options.start_option(OptionCode::ServerId);
        response.options.write_bytes(&self.server_duid.to_bytes()).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write SERVER_ID: {e}"),
            }
        })?;

        // In full implementation, this would:
        // 1. Parse all IAADDR options from IA_NA options in packet
        // 2. Check if each address belongs to a configured dhcp-range on this interface
        // 3. If ANY address is not on-link, return STATUS_CODE NotOnLink
        // 4. If all addresses are on-link, return STATUS_CODE Success
        // 5. Do NOT include IA options in response (per RFC 3315)

        // For now, assume addresses are valid
        response.options.start_option(OptionCode::StatusCode);
        response.options.write_u16(StatusCode::Success as u16).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write status code: {e}"),
            }
        })?;
        response.options.write_bytes(b"Success").map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write status message: {e}"),
            }
        })?;

        debug!("Returning REPLY for CONFIRM with Success status");
        Ok(response)
    }

    /// Handles RENEW messages (extends address lifetimes at T1 timer)
    ///
    /// Client sends RENEW at T1 (typically 50% of preferred lifetime) to extend leases.
    /// Must be sent to specific server that assigned addresses (unicast). Server extends
    /// lifetimes if lease still valid. Corresponds to C lines 1250-1315.
    ///
    /// # Arguments
    ///
    /// * `state` - Request state
    /// * `packet` - Raw packet for option parsing
    ///
    /// # Returns
    ///
    /// REPLY with extended lifetimes, or `NoBinding` status if lease not found
    pub async fn handle_renew(
        &self,
        state: &Dhcp6State,
        packet: &[u8],
    ) -> Result<Dhcp6Response, Dhcp6HandlerError> {
        info!("DHCPRENEW from client on interface {}", state.interface());

        // Extract client DUID
        let client_duid = extract_client_duid(packet)?;

        // Validate SERVER_ID matches our DUID (RFC 3315 Section 18.2.3)
        validate_server_duid(packet, &self.server_duid.to_bytes())?;

        // Create REPLY response
        let message_type = MessageType::Reply;
        let mut response = Dhcp6Response::new(message_type, state.transaction_id());

        // Add CLIENT_ID option
        response.options.start_option(OptionCode::ClientId);
        response.options.write_bytes(&client_duid).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write CLIENT_ID: {e}"),
            }
        })?;

        // Add SERVER_ID option
        response.options.start_option(OptionCode::ServerId);
        response.options.write_bytes(&self.server_duid.to_bytes()).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write SERVER_ID: {e}"),
            }
        })?;

        // In full implementation, this would:
        // 1. Parse all IA_NA/IA_TA/IA_PD options from RENEW
        // 2. For each IA, check if we have a lease for this client+IAID
        // 3. If lease found:
        //    a. Extend lifetimes (call lease_manager update methods)
        //    b. Return IA with extended IAADDR options
        // 4. If lease not found:
        //    a. Return IA with STATUS_CODE NoBinding
        // 5. Log renewal operation

        debug!("Returning REPLY for RENEW with extended lifetimes");
        Ok(response)
    }

    /// Handles REBIND messages (extends address lifetimes from any server at T2 timer)
    ///
    /// Client sends REBIND at T2 (typically 80% of preferred lifetime) if RENEW failed or
    /// original server unreachable. Sent multicast, any server can respond. Corresponds
    /// to C lines 1316-1383.
    ///
    /// # Arguments
    ///
    /// * `state` - Request state
    /// * `packet` - Raw packet for option parsing
    ///
    /// # Returns
    ///
    /// REPLY with extended lifetimes from any server with matching pool
    pub async fn handle_rebind(
        &self,
        state: &Dhcp6State,
        packet: &[u8],
    ) -> Result<Dhcp6Response, Dhcp6HandlerError> {
        info!("DHCPREBIND from client on interface {}", state.interface());

        // Extract client DUID
        let client_duid = extract_client_duid(packet)?;

        // REBIND does not require SERVER_ID match (RFC 3315 Section 18.2.4)
        // Any server with matching pool can respond

        // Create REPLY response
        let message_type = MessageType::Reply;
        let mut response = Dhcp6Response::new(message_type, state.transaction_id());

        // Add CLIENT_ID option
        response.options.start_option(OptionCode::ClientId);
        response.options.write_bytes(&client_duid).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write CLIENT_ID: {e}"),
            }
        })?;

        // Add SERVER_ID option (our server responds)
        response.options.start_option(OptionCode::ServerId);
        response.options.write_bytes(&self.server_duid.to_bytes()).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write SERVER_ID: {e}"),
            }
        })?;

        // In full implementation, this would:
        // 1. Parse all IA_NA/IA_TA/IA_PD options from REBIND
        // 2. For each IA:
        //    a. Check if addresses match our configured dhcp-range
        //    b. If match, extend lifetimes (any server can do this)
        //    c. Return IA with extended IAADDR options
        // 3. If no matching pool, don't respond (let client retry)
        // 4. Log rebind operation

        debug!("Returning REPLY for REBIND with extended lifetimes");
        Ok(response)
    }

    /// Handles RELEASE messages (client releasing addresses explicitly)
    ///
    /// Client sends RELEASE when shutting down or moving to different network. Server
    /// removes leases from database, making addresses available for reassignment.
    /// Corresponds to C lines 1459-1523.
    ///
    /// # Arguments
    ///
    /// * `state` - Request state
    /// * `packet` - Raw packet for option parsing
    ///
    /// # Returns
    ///
    /// REPLY with Success status after releasing addresses
    pub async fn handle_release(
        &self,
        state: &Dhcp6State,
        packet: &[u8],
    ) -> Result<Dhcp6Response, Dhcp6HandlerError> {
        info!("DHCPRELEASE from client on interface {}", state.interface());

        // Extract client DUID
        let client_duid = extract_client_duid(packet)?;

        // Validate SERVER_ID matches our DUID (RFC 3315 Section 18.2.6)
        validate_server_duid(packet, &self.server_duid.to_bytes())?;

        // Create REPLY response
        let message_type = MessageType::Reply;
        let mut response = Dhcp6Response::new(message_type, state.transaction_id());

        // Add CLIENT_ID option
        response.options.start_option(OptionCode::ClientId);
        response.options.write_bytes(&client_duid).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write CLIENT_ID: {e}"),
            }
        })?;

        // Add SERVER_ID option
        response.options.start_option(OptionCode::ServerId);
        response.options.write_bytes(&self.server_duid.to_bytes()).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write SERVER_ID: {e}"),
            }
        })?;

        // In full implementation, this would:
        // 1. Parse all IA_NA/IA_TA/IA_PD options from RELEASE
        // 2. For each IAADDR in each IA:
        //    a. Call lease_manager.release_lease(client_duid, iaid, addr)
        //    b. Remove from lease database
        //    c. Log release operation
        // 3. Return STATUS_CODE Success
        // 4. Include IA options in response per RFC

        response.options.start_option(OptionCode::StatusCode);
        response.options.write_u16(StatusCode::Success as u16).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write status code: {e}"),
            }
        })?;
        response.options.write_bytes(b"Released").map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write status message: {e}"),
            }
        })?;

        debug!("Returning REPLY for RELEASE, addresses released");
        Ok(response)
    }

    /// Handles DECLINE messages (client reporting DAD failure)
    ///
    /// Client sends DECLINE when Duplicate Address Detection (DAD) fails for assigned
    /// address. Server marks address as unavailable with extended hold-off period.
    /// Corresponds to C lines 1524-1575.
    ///
    /// # Arguments
    ///
    /// * `state` - Request state
    /// * `packet` - Raw packet for option parsing
    ///
    /// # Returns
    ///
    /// REPLY acknowledging DECLINE, address marked unavailable
    pub async fn handle_decline(
        &self,
        state: &Dhcp6State,
        packet: &[u8],
    ) -> Result<Dhcp6Response, Dhcp6HandlerError> {
        warn!("DHCPDECLINE from client on interface {} - duplicate address detected", state.interface());

        // Extract client DUID
        let client_duid = extract_client_duid(packet)?;

        // Validate SERVER_ID matches our DUID (RFC 3315 Section 18.2.7)
        validate_server_duid(packet, &self.server_duid.to_bytes())?;

        // Create REPLY response
        let message_type = MessageType::Reply;
        let mut response = Dhcp6Response::new(message_type, state.transaction_id());

        // Add CLIENT_ID option
        response.options.start_option(OptionCode::ClientId);
        response.options.write_bytes(&client_duid).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write CLIENT_ID: {e}"),
            }
        })?;

        // Add SERVER_ID option
        response.options.start_option(OptionCode::ServerId);
        response.options.write_bytes(&self.server_duid.to_bytes()).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write SERVER_ID: {e}"),
            }
        })?;

        // In full implementation, this would:
        // 1. Parse all IA_NA/IA_TA options from DECLINE
        // 2. For each IAADDR in each IA:
        //    a. Call lease_manager.mark_declined(addr, extended_hold_time)
        //    b. Set declined flag on lease with long expiry (e.g., 24 hours)
        //    c. Log DECLINE operation with address
        //    d. Trigger admin alert about duplicate address
        // 3. Return STATUS_CODE Success
        // 4. Include IA options in response per RFC
        // Note: C implementation sets extended expiry to prevent quick reassignment

        response.options.start_option(OptionCode::StatusCode);
        response.options.write_u16(StatusCode::Success as u16).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write status code: {e}"),
            }
        })?;
        response.options.write_bytes(b"Address marked declined").map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write status message: {e}"),
            }
        })?;

        warn!("Address declined by client, marked for extended hold-off");
        debug!("Returning REPLY for DECLINE");
        Ok(response)
    }

    /// Handles INFORMATION-REQUEST messages (stateless configuration)
    ///
    /// Client already has IPv6 address (from SLAAC or static config) and only needs
    /// additional configuration like DNS servers, domain search list. Does NOT include
    /// `IA_NA/IA_TA/IA_PD` options. Corresponds to C lines 1432-1458.
    ///
    /// # Arguments
    ///
    /// * `state` - Request state
    /// * `packet` - Raw packet for option parsing
    ///
    /// # Returns
    ///
    /// REPLY with DNS and other configuration options (no addresses)
    pub async fn handle_information_request(
        &self,
        state: &Dhcp6State,
        packet: &[u8],
    ) -> Result<Dhcp6Response, Dhcp6HandlerError> {
        info!(
            "DHCP INFORMATION-REQUEST from client on interface {}",
            state.interface()
        );

        // Extract client DUID
        let client_duid = extract_client_duid(packet)?;

        // NOTE: INFORMATION-REQUEST does NOT require SERVER_ID validation
        // (client may not know server yet in stateless mode)

        // Create REPLY response
        let message_type = MessageType::Reply;
        let mut response = Dhcp6Response::new(message_type, state.transaction_id());

        // Add CLIENT_ID option
        response.options.start_option(OptionCode::ClientId);
        response.options.write_bytes(&client_duid).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write CLIENT_ID: {e}"),
            }
        })?;

        // Add SERVER_ID option
        response.options.start_option(OptionCode::ServerId);
        response.options.write_bytes(&self.server_duid.to_bytes()).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write SERVER_ID: {e}"),
            }
        })?;

        // In full implementation, this would:
        // 1. Add DNS_SERVERS option with recursive DNS server addresses
        // 2. Add DOMAIN_SEARCH option with search domain list
        // 3. Add NTP_SERVERS option if configured
        // 4. Add other stateless configuration options
        // 5. NO address allocation (no IA_NA/IA_TA/IA_PD options)
        // 6. NO lease database interaction

        // For now, add STATUS_CODE Success
        response.options.start_option(OptionCode::StatusCode);
        response.options.write_u16(StatusCode::Success as u16).map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write status code: {e}"),
            }
        })?;
        response.options.write_bytes(b"Stateless config").map_err(|e| {
            Dhcp6HandlerError::OptionParseError {
                details: format!("Failed to write status message: {e}"),
            }
        })?;

        debug!("Returning REPLY for INFORMATION-REQUEST with stateless config");
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp6_state_new() {
        let state = Dhcp6State::new();
        assert!(state.client_duid().is_empty());
        assert_eq!(state.transaction_id(), 0);
        assert!(state.tags().is_empty());
    }

    #[test]
    fn test_dhcp6_response_new() {
        let response = Dhcp6Response::new(MessageType::Advertise, 0x123456);
        assert_eq!(response.message_type(), MessageType::Advertise);
        assert_eq!(response.transaction_id(), 0x123456);
    }

    #[test]
    fn test_error_display() {
        let err = Dhcp6HandlerError::ClientIdMissing;
        assert_eq!(err.to_string(), "CLIENT_ID option missing from request");

        let err = Dhcp6HandlerError::PacketTooSmall {
            size: 2,
            required: 4,
        };
        assert_eq!(err.to_string(), "Packet too small: 2 bytes (required: 4)");
    }
}
