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

//! # DHCPv6 Protocol Constants and Types
//!
//! This module defines the complete set of DHCPv6 protocol constants, message types, option codes,
//! and status codes as specified in RFC 3315 (DHCPv6), RFC 3633 (Prefix Delegation), and related RFCs.
//!
//! ## Key Protocol Differences from DHCPv4
//!
//! - **TLV-based option encoding**: Not fixed position fields like DHCPv4
//! - **DUID (DHCP Unique Identifier)**: Instead of MAC address for client identification
//! - **Identity Association (IA)**: Concept for grouping addresses/prefixes
//! - **Separate message types**: For stateless (INFORMATION-REQUEST) vs stateful configuration
//! - **Built-in relay support**: With RELAY-FORW/RELAY-REPL messages
//! - **Status codes**: Embedded in replies for granular error reporting
//! - **Prefix delegation**: Support for routing scenarios (RFC 3633)
//!
//! ## Message Format
//!
//! All DHCPv6 messages begin with a 1-byte message type followed by a 3-byte transaction ID,
//! then zero or more TLV-encoded options. Relay messages have a different structure with hop
//! count and link/peer addresses.
//!
//! ## RFC Compliance
//!
//! - RFC 3315: DHCPv6 base protocol (message types, options, DUID types)
//! - RFC 3633: IPv6 Prefix Delegation (IA_PD, IAPREFIX options)
//! - RFC 4361: Node-specific Identifiers for DHCPv4 and DHCPv6
//! - RFC 3646: DNS Configuration Options (DNS_SERVER, DOMAIN_SEARCH)
//! - RFC 5908: NTP Server Option (NTP_SERVER with suboptions)
//! - RFC 6939: Client Link-Layer Address Option (CLIENT_MAC)
//!
//! ## Memory Safety
//!
//! This Rust implementation replaces C `#define` macros with type-safe enums, preventing
//! invalid protocol values through exhaustive matching and bounds-checked conversions.

use std::convert::{TryFrom, Into};
use std::fmt;
use std::net::Ipv6Addr;

// ================================================================================================
// Port Numbers and Multicast Addresses
// ================================================================================================

/// DHCPv6 server listening port (UDP 547)
///
/// Standard UDP port for DHCPv6 servers and relay agents per RFC 3315 Section 5.2.
/// Servers bind to this port to receive client messages (SOLICIT, REQUEST, etc.) and relay
/// agent forwarded messages. Must be privileged port requiring elevated permissions or
/// capability CAP_NET_BIND_SERVICE on Linux.
pub const DHCPV6_SERVER_PORT: u16 = 547;

/// DHCPv6 client listening port (UDP 546)
///
/// Standard UDP port for DHCPv6 clients per RFC 3315 Section 5.2. Clients bind to this port
/// to receive server responses (ADVERTISE, REPLY, RECONFIGURE). Relay agents also use this
/// port when forwarding messages toward clients. Does not require elevated privileges as it
/// is an unprivileged port (>1024).
pub const DHCPV6_CLIENT_PORT: u16 = 546;

/// IPv6 multicast address for all DHCPv6 servers (site-local scope)
///
/// Multicast address FF05::1:3 with site-local scope (FF05) per RFC 3315 Section 5.1.
/// Used by relay agents to forward client messages to all DHCPv6 servers within the
/// administrative site. Site-local scope is broader than link-local, allowing DHCPv6
/// servers to be located on different network segments.
pub const ALL_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3);

/// IPv6 multicast address for all DHCPv6 relay agents and servers (link-local)
///
/// Multicast address FF02::1:2 with link-local scope (FF02) per RFC 3315 Section 5.1.
/// Used by DHCPv6 clients to discover servers and relay agents on the local link. Clients
/// send SOLICIT, CONFIRM, REBIND, and INFORMATION-REQUEST messages to this address when
/// they don't have a specific server address. Link-local scope restricts delivery to the
/// directly attached network segment.
pub const ALL_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

// ================================================================================================
// DHCPv6 Message Types (RFC 3315 Section 5.3)
// ================================================================================================

/// DHCPv6 message types
///
/// Represents the 1-byte message type field at the start of every DHCPv6 message.
/// Enforces type safety by preventing invalid message type values through exhaustive
/// matching and validated conversions.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// SOLICIT (1) - Client-to-server message to locate available DHCPv6 servers
    ///
    /// First message in the 4-message exchange for stateful address assignment
    /// (SOLICIT → ADVERTISE → REQUEST → REPLY). Sent to ALL_RELAY_AGENTS_AND_SERVERS
    /// multicast address. Contains client DUID, IA_NA or IA_TA for addresses, and may
    /// include IA_PD for prefix delegation. Servers respond with ADVERTISE.
    Solicit = 1,

    /// ADVERTISE (2) - Server-to-client message offering configuration parameters
    ///
    /// Second message in 4-message exchange, responding to client SOLICIT. Contains
    /// server DUID, available addresses in IA_NA/IA_TA, prefixes in IA_PD, and server
    /// preference value. Client may receive multiple ADVERTISE messages from different
    /// servers and selects one based on preference and offered parameters.
    Advertise = 2,

    /// REQUEST (3) - Client-to-server message requesting confirmation of offered parameters
    ///
    /// Third message in 4-message exchange, sent after client selects a server from
    /// ADVERTISE messages. Sent to unicast server address (if server provided UNICAST
    /// option) or multicast. Contains client and server DUIDs, and the specific
    /// IA_NA/IA_TA/IA_PD selections. Server responds with REPLY.
    Request = 3,

    /// CONFIRM (4) - Client-to-server message to verify address assignment is still valid
    ///
    /// Used when client with existing address moves to a new link or reboots. Sent to
    /// ALL_RELAY_AGENTS_AND_SERVERS multicast. Does not request new addresses, only
    /// confirms existing addresses in IA_NA are appropriate for the current link.
    Confirm = 4,

    /// RENEW (5) - Client-to-server message to extend address lifetimes
    ///
    /// Sent to the specific server that assigned the addresses (unicast) at T1 timer
    /// expiration (typically 50% of preferred lifetime). Contains client and server
    /// DUIDs and all IAs (IA_NA/IA_TA/IA_PD) for renewal. If RENEW fails, client
    /// attempts REBIND at T2 timer.
    Renew = 5,

    /// REBIND (6) - Client-to-server message to extend address lifetimes from any server
    ///
    /// Sent to ALL_RELAY_AGENTS_AND_SERVERS multicast at T2 timer expiration (typically
    /// 80% of preferred lifetime) if RENEW failed or original server is unreachable.
    /// Any server can respond with REPLY containing extended lifetimes.
    Rebind = 6,

    /// REPLY (7) - Server-to-client message providing configuration and status
    ///
    /// Final message in both 4-message and 2-message exchanges. Responds to REQUEST,
    /// CONFIRM, RENEW, REBIND, RELEASE, DECLINE, and INFORMATION-REQUEST. Contains
    /// committed addresses in IA_NA/IA_TA with lifetimes, prefixes in IA_PD, DNS
    /// servers, domain search list, and status codes.
    Reply = 7,

    /// RELEASE (8) - Client-to-server message releasing assigned addresses
    ///
    /// Sent when client no longer needs addresses (shutdown, moving to different network).
    /// Sent to the specific server that assigned addresses (unicast). Contains client
    /// and server DUIDs and all IAs to be released. Releases make addresses available
    /// for reassignment.
    Release = 8,

    /// DECLINE (9) - Client-to-server message indicating assigned addresses are already in use
    ///
    /// Sent when client detects Duplicate Address Detection (DAD) failure per RFC 4862.
    /// Sent to the specific server that assigned addresses (unicast). Contains client
    /// and server DUIDs and IAs with problematic addresses. Server marks addresses as
    /// unavailable for reassignment.
    Decline = 9,

    /// RECONFIGURE (10) - Server-to-client message instructing client to initiate new transaction
    ///
    /// Allows server to push configuration changes to clients. Sent to client unicast
    /// address. Contains reconfigure message type (RENEW or INFORMATION-REQUEST) and
    /// authentication option (mandatory for security). Requires prior client acceptance
    /// via RECONF_ACCEPT option.
    Reconfigure = 10,

    /// INFORMATION-REQUEST (11) - Client-to-server message requesting configuration without addresses
    ///
    /// Used for stateless DHCPv6 where client obtains IPv6 address via SLAAC but needs
    /// additional parameters (DNS servers, domain search, NTP servers). Sent to
    /// ALL_RELAY_AGENTS_AND_SERVERS multicast. Does not contain IA_NA, IA_TA, or IA_PD.
    InformationRequest = 11,

    /// RELAY-FORW (12) - Relay-agent-to-server message encapsulating client message
    ///
    /// Used by relay agents to forward client messages to servers on different links.
    /// Contains hop count, link address, peer address, and encapsulated client message
    /// in RELAY_MSG option. Enables DHCPv6 to work across routers.
    RelayForw = 12,

    /// RELAY-REPL (13) - Server-to-relay-agent message encapsulating server response
    ///
    /// Sent by servers in response to RELAY-FORW messages. Contains same hop count,
    /// link address, and peer address as corresponding RELAY-FORW, plus encapsulated
    /// server message in RELAY_MSG option. Relay agents forward toward client.
    RelayRepl = 13,
}

impl MessageType {
    /// Returns the numeric value of the message type as a u8
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for MessageType {
    type Error = InvalidMessageType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::Solicit),
            2 => Ok(MessageType::Advertise),
            3 => Ok(MessageType::Request),
            4 => Ok(MessageType::Confirm),
            5 => Ok(MessageType::Renew),
            6 => Ok(MessageType::Rebind),
            7 => Ok(MessageType::Reply),
            8 => Ok(MessageType::Release),
            9 => Ok(MessageType::Decline),
            10 => Ok(MessageType::Reconfigure),
            11 => Ok(MessageType::InformationRequest),
            12 => Ok(MessageType::RelayForw),
            13 => Ok(MessageType::RelayRepl),
            _ => Err(InvalidMessageType(value)),
        }
    }
}

impl Into<u8> for MessageType {
    fn into(self) -> u8 {
        self.as_u8()
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            MessageType::Solicit => "SOLICIT",
            MessageType::Advertise => "ADVERTISE",
            MessageType::Request => "REQUEST",
            MessageType::Confirm => "CONFIRM",
            MessageType::Renew => "RENEW",
            MessageType::Rebind => "REBIND",
            MessageType::Reply => "REPLY",
            MessageType::Release => "RELEASE",
            MessageType::Decline => "DECLINE",
            MessageType::Reconfigure => "RECONFIGURE",
            MessageType::InformationRequest => "INFORMATION-REQUEST",
            MessageType::RelayForw => "RELAY-FORW",
            MessageType::RelayRepl => "RELAY-REPL",
        };
        write!(f, "{}", name)
    }
}

/// Error type for invalid DHCPv6 message type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMessageType(pub u8);

impl fmt::Display for InvalidMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid DHCPv6 message type: {} (valid range: 1-13)", self.0)
    }
}

impl std::error::Error for InvalidMessageType {}

// ================================================================================================
// DHCPv6 Option Codes (RFC 3315 and Extensions)
// ================================================================================================

/// DHCPv6 option codes for TLV (Type-Length-Value) encoding
///
/// Represents the 2-byte option code field in DHCPv6 TLV options. Unlike DHCPv4 which
/// uses fixed-position fields, DHCPv6 employs TLV encoding for all options, providing
/// greater extensibility. Enforces type safety by preventing invalid option codes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionCode {
    /// CLIENT_ID (1) - Client DUID (DHCP Unique Identifier)
    ///
    /// Mandatory in all client messages. Uniquely identifies client across network moves
    /// and reboots. DUID types: DUID-LLT (link-layer + time), DUID-EN (enterprise number),
    /// DUID-LL (link-layer only). Format: 2-byte type + variable-length identifier.
    ClientId = 1,

    /// SERVER_ID (2) - Server DUID
    ///
    /// Included in server ADVERTISE and REPLY messages to identify the responding server.
    /// Clients copy this option into REQUEST, RENEW, RELEASE, and DECLINE messages to
    /// direct messages to specific server.
    ServerId = 2,

    /// IA_NA (3) - Identity Association for Non-temporary Addresses
    ///
    /// Container for non-temporary address assignment. Contains 4-byte IAID, 4-byte T1
    /// timer (when to RENEW), 4-byte T2 timer (when to REBIND), followed by IA Address
    /// options (IAADDR) with actual IPv6 addresses and lifetimes.
    IaNa = 3,

    /// IA_TA (4) - Identity Association for Temporary Addresses
    ///
    /// Container for temporary address assignment per RFC 4941 (Privacy Extensions).
    /// Used for privacy-sensitive communications. Contains 4-byte IAID followed by
    /// IA Address options. No T1/T2 timers.
    IaTa = 4,

    /// IAADDR (5) - IA Address
    ///
    /// Actual IPv6 address within IA_NA or IA_TA. Contains 16-byte IPv6 address,
    /// 4-byte preferred lifetime, and 4-byte valid lifetime. May contain STATUS_CODE
    /// sub-option for per-address error reporting.
    IaAddr = 5,

    /// ORO (6) - Option Request Option
    ///
    /// List of option codes client wants server to provide. Contains sequence of 2-byte
    /// option codes. Used in SOLICIT, REQUEST, RENEW, REBIND, INFORMATION-REQUEST.
    Oro = 6,

    /// PREFERENCE (7) - Server Preference
    ///
    /// Server preference value (0-255) in ADVERTISE messages. Higher values indicate
    /// greater server preference. Value 255 instructs client to immediately send REQUEST
    /// without waiting for other ADVERTISEs.
    Preference = 7,

    /// ELAPSED_TIME (8) - Elapsed Time
    ///
    /// Time elapsed since client began current transaction. Contains 2-byte value in
    /// centiseconds (1/100th second). Value 0xFFFF indicates 655.35 seconds or greater.
    ElapsedTime = 8,

    /// RELAY_MSG (9) - Relay Message
    ///
    /// Encapsulated DHCPv6 message within RELAY-FORW or RELAY-REPL. Contains complete
    /// original message. Allows relay agents to forward messages between links while
    /// preserving original message content.
    RelayMsg = 9,

    /// AUTH (11) - Authentication
    ///
    /// Message authentication information. Contains protocol type, algorithm, replay
    /// detection method (RDM), replay detection value, and authentication information.
    /// Mandatory in RECONFIGURE messages. Note: Option code 10 is unassigned.
    Auth = 11,

    /// UNICAST (12) - Server Unicast
    ///
    /// Server IPv6 address for unicast messaging. Included in ADVERTISE or REPLY to
    /// tell client it may unicast subsequent messages directly to server instead of
    /// using multicast. Contains 16-byte server IPv6 address.
    Unicast = 12,

    /// STATUS_CODE (13) - Status Code
    ///
    /// Success or error status. Contains 2-byte status code followed by UTF-8 status
    /// message. Can appear at message level or within IA_NA/IA_TA/IA_PD options for
    /// per-association status.
    StatusCode = 13,

    /// RAPID_COMMIT (14) - Rapid Commit
    ///
    /// Signals 2-message exchange instead of 4-message. Zero-length option. Client
    /// includes in SOLICIT, server responds with REPLY if configured to allow rapid
    /// commit. Reduces address assignment from 4 messages to 2.
    RapidCommit = 14,

    /// USER_CLASS (15) - User Class
    ///
    /// User class categorization. Contains one or more opaque data fields identifying
    /// user class (e.g., "engineering", "guest"). Allows servers to provide different
    /// configuration based on user category.
    UserClass = 15,

    /// VENDOR_CLASS (16) - Vendor Class
    ///
    /// Vendor class identification. Contains 4-byte enterprise number (IANA-assigned)
    /// followed by vendor class data fields. Identifies device vendor and model for
    /// vendor-specific configuration.
    VendorClass = 16,

    /// VENDOR_OPTS (17) - Vendor-specific Information
    ///
    /// Vendor-specific options. Contains 4-byte enterprise number followed by
    /// vendor-defined option data. Allows vendors to extend DHCPv6 with proprietary
    /// options without IANA registration.
    VendorOpts = 17,

    /// INTERFACE_ID (18) - Interface-ID
    ///
    /// Relay agent interface identifier. Opaque value identifying client-facing interface.
    /// Included in RELAY-FORW messages by relay agent, copied to RELAY-REPL by server.
    InterfaceId = 18,

    /// RECONFIGURE_MSG (19) - Reconfigure Message
    ///
    /// Type of reconfiguration requested in RECONFIGURE message. Contains 1-byte message
    /// type: RENEW (5) or INFORMATION-REQUEST (11). Tells client what type of transaction
    /// to initiate in response to server's RECONFIGURE.
    ReconfMsg = 19,

    /// RECONF_ACCEPT (20) - Reconfigure Accept
    ///
    /// Client willingness to accept RECONFIGURE messages. Zero-length option. Client
    /// includes in SOLICIT, REQUEST, RENEW, or REBIND to indicate it will accept
    /// authenticated RECONFIGURE messages from server.
    ReconfAccept = 20,

    /// DNS_SERVER (23) - DNS Recursive Name Server
    ///
    /// List of DNS server IPv6 addresses per RFC 3646. Contains one or more 16-byte
    /// IPv6 addresses of recursive DNS servers in preference order. Essential for
    /// name resolution. Note: Options 21-22 are SIP servers.
    DnsServers = 23,

    /// DOMAIN_SEARCH (24) - Domain Search List
    ///
    /// DNS domain search list per RFC 3646. Contains one or more domain names encoded
    /// in DNS wire format. Client appends these domains to unqualified hostnames during
    /// resolution.
    DomainList = 24,

    /// IA_PD (25) - Identity Association for Prefix Delegation
    ///
    /// Container for delegated prefix assignment per RFC 3633. Used by requesting routers
    /// to obtain IPv6 prefix(es) for downstream networks. Contains 4-byte IAID, 4-byte
    /// T1 timer, 4-byte T2 timer, followed by IA Prefix options.
    IaPd = 25,

    /// IAPREFIX (26) - IA Prefix
    ///
    /// Actual delegated prefix within IA_PD per RFC 3633. Contains 4-byte preferred
    /// lifetime, 4-byte valid lifetime, 1-byte prefix length (0-128), and 16-byte IPv6
    /// prefix. Note: Options 27-31 are various DHCPv6 extensions.
    IaPrefix = 26,

    /// REFRESH_TIME (32) - Information Refresh Time
    ///
    /// Suggested interval for stateless configuration refresh per RFC 4242. Contains
    /// 4-byte time in seconds. Server includes in REPLY to INFORMATION-REQUEST to tell
    /// client how often to refresh stateless configuration.
    RefreshTime = 32,

    /// REMOTE_ID (37) - Relay Agent Remote-ID
    ///
    /// Relay agent identifier for remote client per RFC 4649. Contains 4-byte enterprise
    /// number followed by opaque remote ID. Identifies remote client's location or
    /// connection properties. Note: Options 33-36 are other services.
    RemoteId = 37,

    /// SUBSCRIBER_ID (38) - Relay Agent Subscriber-ID
    ///
    /// Relay agent subscriber identification per RFC 4580. Contains opaque subscriber
    /// identifier (e.g., account number, circuit ID). Identifies subscribing customer
    /// for accounting and billing.
    SubscriberId = 38,

    /// FQDN (39) - Client FQDN
    ///
    /// Fully Qualified Domain Name option per RFC 4704. Contains flags and domain name
    /// in DNS wire format. Coordinates DNS updates between client and server. Enables
    /// dynamic DNS integration. Note: Options 40-55 are various extensions.
    Fqdn = 39,

    /// NTP_SERVER (56) - NTP Server
    ///
    /// Network Time Protocol server configuration per RFC 5908. Contains one or more
    /// sub-options specifying NTP server addresses or FQDNs. Essential for time
    /// synchronization. Note: Options 40-55 include many extensions.
    NtpServer = 56,

    /// CLIENT_MAC (79) - Client Link-Layer Address
    ///
    /// Client hardware address per RFC 6939. Contains 2-byte link-layer type followed
    /// by link-layer address (typically 6-byte MAC address). Inserted by relay agent.
    /// Allows server to use MAC address for identification and reservations.
    /// Note: Options 57-78 include many vendor and protocol extensions.
    ClientMac = 79,
}

impl OptionCode {
    /// Returns the numeric value of the option code as a u16
    pub const fn as_u16(&self) -> u16 {
        *self as u16
    }
}

impl TryFrom<u16> for OptionCode {
    type Error = InvalidOptionCode;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(OptionCode::ClientId),
            2 => Ok(OptionCode::ServerId),
            3 => Ok(OptionCode::IaNa),
            4 => Ok(OptionCode::IaTa),
            5 => Ok(OptionCode::IaAddr),
            6 => Ok(OptionCode::Oro),
            7 => Ok(OptionCode::Preference),
            8 => Ok(OptionCode::ElapsedTime),
            9 => Ok(OptionCode::RelayMsg),
            11 => Ok(OptionCode::Auth),
            12 => Ok(OptionCode::Unicast),
            13 => Ok(OptionCode::StatusCode),
            14 => Ok(OptionCode::RapidCommit),
            15 => Ok(OptionCode::UserClass),
            16 => Ok(OptionCode::VendorClass),
            17 => Ok(OptionCode::VendorOpts),
            18 => Ok(OptionCode::InterfaceId),
            19 => Ok(OptionCode::ReconfMsg),
            20 => Ok(OptionCode::ReconfAccept),
            23 => Ok(OptionCode::DnsServers),
            24 => Ok(OptionCode::DomainList),
            25 => Ok(OptionCode::IaPd),
            26 => Ok(OptionCode::IaPrefix),
            32 => Ok(OptionCode::RefreshTime),
            37 => Ok(OptionCode::RemoteId),
            38 => Ok(OptionCode::SubscriberId),
            39 => Ok(OptionCode::Fqdn),
            56 => Ok(OptionCode::NtpServer),
            79 => Ok(OptionCode::ClientMac),
            _ => Err(InvalidOptionCode(value)),
        }
    }
}

impl Into<u16> for OptionCode {
    fn into(self) -> u16 {
        self.as_u16()
    }
}

impl fmt::Display for OptionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            OptionCode::ClientId => "CLIENT_ID",
            OptionCode::ServerId => "SERVER_ID",
            OptionCode::IaNa => "IA_NA",
            OptionCode::IaTa => "IA_TA",
            OptionCode::IaAddr => "IAADDR",
            OptionCode::Oro => "ORO",
            OptionCode::Preference => "PREFERENCE",
            OptionCode::ElapsedTime => "ELAPSED_TIME",
            OptionCode::RelayMsg => "RELAY_MSG",
            OptionCode::Auth => "AUTH",
            OptionCode::Unicast => "UNICAST",
            OptionCode::StatusCode => "STATUS_CODE",
            OptionCode::RapidCommit => "RAPID_COMMIT",
            OptionCode::UserClass => "USER_CLASS",
            OptionCode::VendorClass => "VENDOR_CLASS",
            OptionCode::VendorOpts => "VENDOR_OPTS",
            OptionCode::InterfaceId => "INTERFACE_ID",
            OptionCode::ReconfMsg => "RECONFIGURE_MSG",
            OptionCode::ReconfAccept => "RECONF_ACCEPT",
            OptionCode::DnsServers => "DNS_SERVER",
            OptionCode::DomainList => "DOMAIN_SEARCH",
            OptionCode::IaPd => "IA_PD",
            OptionCode::IaPrefix => "IAPREFIX",
            OptionCode::RefreshTime => "REFRESH_TIME",
            OptionCode::RemoteId => "REMOTE_ID",
            OptionCode::SubscriberId => "SUBSCRIBER_ID",
            OptionCode::Fqdn => "FQDN",
            OptionCode::NtpServer => "NTP_SERVER",
            OptionCode::ClientMac => "CLIENT_MAC",
        };
        write!(f, "{}", name)
    }
}

/// Error type for invalid DHCPv6 option code values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidOptionCode(pub u16);

impl fmt::Display for InvalidOptionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid DHCPv6 option code: {}", self.0)
    }
}

impl std::error::Error for InvalidOptionCode {}

// ================================================================================================
// DHCPv6 Status Codes (RFC 3315 Section 24.4)
// ================================================================================================

/// DHCPv6 status codes for error reporting
///
/// Status codes appear in the STATUS_CODE option (option code 13) and provide granular
/// error reporting. Can appear at message level for general issues or within IA_NA/IA_TA/IA_PD
/// options for per-association status.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatusCode {
    /// Success (0) - Transaction completed successfully
    ///
    /// Included in STATUS_CODE option at message level or within IA_NA/IA_TA/IA_PD to
    /// indicate successful operation. Default assumption if STATUS_CODE option absent.
    /// Used in REPLY messages to confirm successful address assignment, renewal, release,
    /// or configuration.
    Success = 0,

    /// UnspecFail (1) - Unspecified failure
    ///
    /// Generic error when no more specific status code applies. Server uses when
    /// encountering internal error, resource exhaustion, or other unexpected condition.
    /// Client should not retry immediately. Equivalent to "Internal Server Error" in HTTP.
    UnspecFail = 1,

    /// NoAddrsAvail (2) - No addresses available for assignment
    ///
    /// Included in STATUS_CODE option within IA_NA or IA_TA when server has no free
    /// addresses in requested address pool. May be temporary (addresses currently allocated)
    /// or permanent (pool exhausted). Client may retry later with exponential backoff.
    NoAddrsAvail = 2,

    /// NoBinding (3) - Server has no binding for requesting client
    ///
    /// Included in message-level STATUS_CODE in response to RENEW, REBIND, RELEASE, or
    /// DECLINE when server has no record of previous address assignment to this client.
    /// May occur if server restarted and lost lease database. Client must stop using
    /// addresses and restart with SOLICIT.
    NoBinding = 3,

    /// NotOnLink (4) - Client's addresses not appropriate for link
    ///
    /// Returned in message-level STATUS_CODE in response to CONFIRM message when client's
    /// existing addresses are not valid for the link it's currently attached to. Client
    /// has moved to different network segment. Client must stop using addresses and
    /// initiate new SOLICIT.
    NotOnLink = 4,

    /// UseMulticast (5) - Client must use multicast, not unicast
    ///
    /// Returned when client sent message to server unicast address without server having
    /// provided UNICAST option authorizing unicast. Enforces protocol requirement that
    /// clients use multicast unless explicitly allowed unicast. Client must resend message
    /// to ALL_RELAY_AGENTS_AND_SERVERS multicast address.
    UseMulticast = 5,
}

impl StatusCode {
    /// Returns the numeric value of the status code as a u16
    pub const fn as_u16(&self) -> u16 {
        *self as u16
    }

    /// Returns a human-readable description of the status code
    pub const fn description(&self) -> &'static str {
        match self {
            StatusCode::Success => "Success",
            StatusCode::UnspecFail => "Unspecified failure",
            StatusCode::NoAddrsAvail => "No addresses available",
            StatusCode::NoBinding => "No binding exists",
            StatusCode::NotOnLink => "Not on link",
            StatusCode::UseMulticast => "Use multicast",
        }
    }

    /// Returns whether this status code indicates success
    pub const fn is_success(&self) -> bool {
        matches!(self, StatusCode::Success)
    }

    /// Returns whether this status code indicates an error
    pub const fn is_error(&self) -> bool {
        !self.is_success()
    }
}

impl TryFrom<u16> for StatusCode {
    type Error = InvalidStatusCode;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(StatusCode::Success),
            1 => Ok(StatusCode::UnspecFail),
            2 => Ok(StatusCode::NoAddrsAvail),
            3 => Ok(StatusCode::NoBinding),
            4 => Ok(StatusCode::NotOnLink),
            5 => Ok(StatusCode::UseMulticast),
            _ => Err(InvalidStatusCode(value)),
        }
    }
}

impl Into<u16> for StatusCode {
    fn into(self) -> u16 {
        self.as_u16()
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.description(), self.as_u16())
    }
}

/// Error type for invalid DHCPv6 status code values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidStatusCode(pub u16);

impl fmt::Display for InvalidStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid DHCPv6 status code: {} (valid range: 0-5)", self.0)
    }
}

impl std::error::Error for InvalidStatusCode {}

// ================================================================================================
// DUID Types (RFC 3315 Section 9)
// ================================================================================================

/// DUID-LLT (1) - DUID Based on Link-layer Address Plus Time
///
/// Contains hardware type, time (seconds since midnight UTC 2000-01-01), and link-layer
/// address. Most common DUID type. Time component ensures uniqueness even if link-layer
/// address reused. Format: 2-byte type (1) + 2-byte hardware type + 4-byte time + link-layer
/// address.
pub const DUID_LLT: u16 = 1;

/// DUID-EN (2) - DUID Assigned by Vendor Based on Enterprise Number
///
/// Contains IANA-assigned enterprise number and vendor-assigned identifier. Used by vendors
/// with registered enterprise numbers. Format: 2-byte type (2) + 4-byte enterprise number +
/// variable-length vendor-assigned identifier.
pub const DUID_EN: u16 = 2;

/// DUID-LL (3) - DUID Based on Link-layer Address
///
/// Contains hardware type and link-layer address only (no time component). Simpler than
/// DUID-LLT but uniqueness depends entirely on link-layer address uniqueness. Format:
/// 2-byte type (3) + 2-byte hardware type + link-layer address.
pub const DUID_LL: u16 = 3;

// ================================================================================================
// NTP Server Suboption Types (RFC 5908 Section 4)
// ================================================================================================

/// NTP Server Address suboption (1)
///
/// NTP server unicast IPv6 address per RFC 5908 Section 4.1. Sub-option within OPTION6_NTP_SERVER
/// containing 16-byte IPv6 address of NTP server. Multiple instances allowed for redundancy.
/// Client contacts server using standard NTP protocol on UDP port 123. Most common NTP
/// configuration method.
pub const NTP_SUBOPTION_SRV_ADDR: u16 = 1;

/// NTP Multicast Address suboption (2)
///
/// NTP server multicast IPv6 address per RFC 5908 Section 4.2. Sub-option within
/// OPTION6_NTP_SERVER containing 16-byte IPv6 multicast address. Client joins multicast
/// group and receives NTP broadcasts. Less common than unicast but useful for local time
/// distribution. Typical multicast address: FF05::101.
pub const NTP_SUBOPTION_MC_ADDR: u16 = 2;

/// NTP Server FQDN suboption (3)
///
/// NTP server Fully Qualified Domain Name per RFC 5908 Section 4.3. Sub-option within
/// OPTION6_NTP_SERVER containing DNS name in wire format. Client resolves FQDN via DNS
/// (AAAA query) to obtain server IPv6 address. Useful for pool.ntp.org and round-robin
/// DNS-based NTP services. Client must have DNS resolver configured before resolving.
pub const NTP_SUBOPTION_SRV_FQDN: u16 = 3;

// ================================================================================================
// Tests
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversions() {
        // Test valid conversions
        assert_eq!(MessageType::try_from(1).unwrap(), MessageType::Solicit);
        assert_eq!(MessageType::try_from(7).unwrap(), MessageType::Reply);
        assert_eq!(MessageType::try_from(13).unwrap(), MessageType::RelayRepl);

        // Test invalid conversion
        assert!(MessageType::try_from(0).is_err());
        assert!(MessageType::try_from(14).is_err());
        assert!(MessageType::try_from(255).is_err());

        // Test Into<u8>
        let msg_type = MessageType::Solicit;
        let value: u8 = msg_type.into();
        assert_eq!(value, 1);
    }

    #[test]
    fn test_message_type_display() {
        assert_eq!(format!("{}", MessageType::Solicit), "SOLICIT");
        assert_eq!(format!("{}", MessageType::InformationRequest), "INFORMATION-REQUEST");
    }

    #[test]
    fn test_option_code_conversions() {
        // Test valid conversions
        assert_eq!(OptionCode::try_from(1).unwrap(), OptionCode::ClientId);
        assert_eq!(OptionCode::try_from(23).unwrap(), OptionCode::DnsServers);
        assert_eq!(OptionCode::try_from(79).unwrap(), OptionCode::ClientMac);

        // Test invalid conversion
        assert!(OptionCode::try_from(0).is_err());
        assert!(OptionCode::try_from(10).is_err()); // Gap in numbering
        assert!(OptionCode::try_from(1000).is_err());

        // Test Into<u16>
        let opt_code = OptionCode::ClientId;
        let value: u16 = opt_code.into();
        assert_eq!(value, 1);
    }

    #[test]
    fn test_option_code_display() {
        assert_eq!(format!("{}", OptionCode::ClientId), "CLIENT_ID");
        assert_eq!(format!("{}", OptionCode::DnsServers), "DNS_SERVER");
    }

    #[test]
    fn test_status_code_conversions() {
        // Test valid conversions
        assert_eq!(StatusCode::try_from(0).unwrap(), StatusCode::Success);
        assert_eq!(StatusCode::try_from(2).unwrap(), StatusCode::NoAddrsAvail);
        assert_eq!(StatusCode::try_from(5).unwrap(), StatusCode::UseMulticast);

        // Test invalid conversion
        assert!(StatusCode::try_from(6).is_err());
        assert!(StatusCode::try_from(100).is_err());

        // Test Into<u16>
        let status = StatusCode::Success;
        let value: u16 = status.into();
        assert_eq!(value, 0);
    }

    #[test]
    fn test_status_code_helpers() {
        assert!(StatusCode::Success.is_success());
        assert!(!StatusCode::Success.is_error());
        assert!(!StatusCode::NoAddrsAvail.is_success());
        assert!(StatusCode::NoAddrsAvail.is_error());
    }

    #[test]
    fn test_status_code_display() {
        assert_eq!(format!("{}", StatusCode::Success), "Success (0)");
        assert_eq!(format!("{}", StatusCode::NoBinding), "No binding exists (3)");
    }

    #[test]
    fn test_port_constants() {
        assert_eq!(DHCPV6_SERVER_PORT, 547);
        assert_eq!(DHCPV6_CLIENT_PORT, 546);
    }

    #[test]
    fn test_multicast_addresses() {
        // FF05::1:3
        assert_eq!(ALL_SERVERS, Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3));
        // FF02::1:2
        assert_eq!(ALL_RELAY_AGENTS_AND_SERVERS, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2));
    }

    #[test]
    fn test_duid_constants() {
        assert_eq!(DUID_LLT, 1);
        assert_eq!(DUID_EN, 2);
        assert_eq!(DUID_LL, 3);
    }

    #[test]
    fn test_ntp_suboption_constants() {
        assert_eq!(NTP_SUBOPTION_SRV_ADDR, 1);
        assert_eq!(NTP_SUBOPTION_MC_ADDR, 2);
        assert_eq!(NTP_SUBOPTION_SRV_FQDN, 3);
    }
}
