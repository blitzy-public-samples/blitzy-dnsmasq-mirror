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

//! DHCPv4 Server Module
//!
//! This module provides a complete, memory-safe implementation of DHCPv4 server
//! functionality per RFC 2131 and RFC 2132, replacing the C implementation in
//! `src/dhcp.c` and `src/rfc2131.c`.
//!
//! # Overview
//!
//! The DHCPv4 subsystem implements the Dynamic Host Configuration Protocol version 4,
//! enabling automatic IP address allocation, network configuration distribution, and
//! lease management for IPv4 networks. This Rust implementation maintains exact
//! behavioral parity with dnsmasq's proven C implementation while eliminating entire
//! classes of memory-safety vulnerabilities.
//!
//! # Architecture
//!
//! The module is organized into five submodules that cleanly separate concerns:
//!
//! - **`protocol`**: Wire-format packet structures, message types, option codes, and
//!   constants per RFC 2131/2132. Provides type-safe enums replacing C preprocessor
//!   macros and enables exhaustive pattern matching.
//!
//! - **`options`**: Safe option parsing and building with automatic bounds checking.
//!   Eliminates buffer overflows in option processing through Rust slice types and
//!   validates UTF-8 in string options.
//!
//! - **`ping`**: Asynchronous ping-before-offer conflict detection using ICMP echo
//!   requests. Prevents duplicate IP assignment with 500ms timeout and 90-second
//!   result caching.
//!
//! - **`handler`**: Protocol state machine implementing RFC 2131 message processing.
//!   Handles all message types (DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE/DECLINE/INFORM)
//!   with deterministic lease allocation and response generation.
//!
//! - **`server`**: Async server runtime coordinating socket management, packet reception,
//!   protocol handling, and integration with lease database and DNS cache.
//!
//! # DHCPv4 Protocol Flow
//!
//! ## Standard 4-Message Exchange
//!
//! ```text
//! Client                    Server
//!   |                         |
//!   |  DHCPDISCOVER (bcast)   |
//!   |------------------------>|
//!   |                         |
//!   |    DHCPOFFER (ucast)    |
//!   |<------------------------|
//!   |                         |
//!   |  DHCPREQUEST (bcast)    |
//!   |------------------------>|
//!   |                         |
//!   |     DHCPACK (ucast)     |
//!   |<------------------------|
//!   |                         |
//! ```
//!
//! ## Rapid Commit (2-Message Optimization)
//!
//! When client includes `OPTION_RAPID_COMMIT` in DISCOVER and server supports it:
//!
//! ```text
//! Client                    Server
//!   |                         |
//!   |  DHCPDISCOVER (bcast)   |
//!   |  + rapid-commit opt     |
//!   |------------------------>|
//!   |                         |
//!   |     DHCPACK (ucast)     |
//!   |  + rapid-commit opt     |
//!   |<------------------------|
//!   |                         |
//! ```
//!
//! # Lease Allocation Algorithm
//!
//! The server allocates IP addresses using the following priority order:
//!
//! 1. **Static Reservation**: If client MAC/ID matches a configured static host,
//!    allocate the reserved address (if available)
//! 2. **Existing Lease Renewal**: If client has an active lease, renew same address
//! 3. **Requested Address**: If client requests specific address in DISCOVER/REQUEST
//!    and it's within configured range and available, allocate it
//! 4. **Next Available**: Select next available address from configured range(s),
//!    cycling through pools in order
//! 5. **Ping-Before-Offer**: Before offering address, send ICMP echo to verify
//!    it's not already in use (configurable timeout, default 500ms)
//! 6. **ARP Conflict Detection**: Check ARP cache for MAC conflicts
//!
//! If all addresses are allocated, return DHCPNAK to REQUEST or no response to DISCOVER.
//!
//! # Relay Agent Support
//!
//! Supports DHCP relay agents per RFC 1542 for multi-subnet deployments:
//!
//! - **`giaddr` Processing**: When giaddr field is non-zero, packet arrived via relay.
//!   Server uses giaddr to select appropriate address pool (DHCP context) and sends
//!   response back through relay.
//!
//! - **Option 82 Handling**: Relay Agent Information Option containing circuit-id and
//!   remote-id suboptions. Server preserves option 82 in responses and can use it for
//!   lease identification and subnet selection.
//!
//! - **Broadcast Flag**: Server respects BROADCAST flag in DHCP requests to determine
//!   whether to send response as broadcast or unicast.
//!
//! # PXE Boot Integration
//!
//! Supports Pre-boot Execution Environment (PXE) network booting:
//!
//! - **Architecture Detection**: Examines `OPTION_ARCH` (93) to identify client
//!   architecture (BIOS, UEFI x64, UEFI IA32, etc.)
//!
//! - **Boot File Configuration**: Provides boot filename (`OPTION_FILENAME`, 67) and
//!   TFTP server address (`OPTION_SNAME`, 66) based on client architecture
//!
//! - **Proxy DHCP Mode**: Separate PXE socket on port 4011 serves PXE-specific options
//!   without IP allocation (coordinated with main DHCP on port 67)
//!
//! - **Vendor-Specific Options**: Handles PXE vendor options (43) with suboptions for
//!   boot menu, discovery control, and multicast configuration
//!
//! # Memory Safety Improvements
//!
//! This Rust implementation eliminates the following vulnerability classes present
//! in the C implementation:
//!
//! ## Buffer Overflows in Option Parsing
//!
//! - **C Version**: Manual bounds checking with potential off-by-one errors in
//!   option extraction, especially with option overload (options in sname/file fields)
//! - **Rust Version**: Slice types with automatic bounds checking, panic-free indexing
//!   via `get()`, and validated UTF-8 for string options
//!
//! ## Use-After-Free in Lease Management
//!
//! - **C Version**: Manual lease structure allocation/deallocation with complex pointer
//!   relationships between lease database, hash table, and LRU list
//! - **Rust Version**: Ownership system prevents use-after-free, `Arc<Mutex<Lease>>`
//!   for shared lease references, automatic cleanup on Drop
//!
//! ## Null Pointer Dereferences in Packet Handling
//!
//! - **C Version**: Functions returning NULL on error with inconsistent null checks,
//!   especially in option finding and context matching
//! - **Rust Version**: `Option<T>` and `Result<T, E>` types enforce explicit null/error
//!   handling at compile time, preventing null dereferences
//!
//! ## Integer Overflows in Timeout Calculations
//!
//! - **C Version**: Manual overflow checks in lease expiry and timeout arithmetic
//! - **Rust Version**: Checked arithmetic or explicit saturation for time calculations,
//!   `Duration` type for type-safe time handling
//!
//! ## Race Conditions in Signal Handling
//!
//! - **C Version**: Signal handlers accessing global state with potential TOCTOU races
//! - **Rust Version**: Tokio signal handling with async/await, no shared mutable globals,
//!   channel-based communication between event handlers
//!
//! # Integration Points
//!
//! ## Network Layer Integration
//!
//! - **Socket Management**: Uses `network::sockets` module for UDP socket creation,
//!   binding to port 67 (DHCP) and optionally port 4011 (PXE)
//! - **Interface Enumeration**: Queries `network::interfaces` for active interfaces,
//!   IP addresses, and netmasks to determine which contexts apply
//! - **Broadcast Handling**: Configures `SO_BROADCAST` socket option for broadcast
//!   packet transmission (OFFER/ACK responses)
//!
//! ## Lease Database Integration
//!
//! - **Persistence**: Stores allocated leases in lease database (`dhcp::lease` module)
//!   with atomic file updates for crash recovery
//! - **Expiry Management**: Queries lease database for expired leases, triggers
//!   cleanup, and maintains active lease count per address pool
//! - **Hostname Storage**: Associates client hostnames with leases for DNS integration
//!
//! ## DNS Cache Integration
//!
//! - **Dynamic DNS Updates**: Adds lease hostname-to-IP mappings to DNS cache for
//!   authoritative responses to forward and reverse queries
//! - **Hostname Resolution**: Queries DNS cache for existing A/AAAA records to resolve
//!   client-requested hostnames
//! - **Cache Invalidation**: Removes DNS entries when leases expire or are released
//!
//! ## Configuration Subsystem
//!
//! - **DHCP Contexts**: Address pools with range start/end, netmask, lease duration,
//!   router, DNS servers, and domain name
//! - **Static Hosts**: MAC-to-IP reservations loaded from configuration file or
//!   `/etc/ethers`
//! - **Options Configuration**: Per-context or per-host DHCP option overrides
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dnsmasq::dhcp::v4::{DhcpServer, ServerConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize server configuration
//!     let config = ServerConfig::builder()
//!         .bind_address("0.0.0.0:67".parse()?)
//!         .enable_pxe(true)
//!         .lease_file("/var/lib/dnsmasq/dnsmasq.leases")
//!         .build()?;
//!
//!     // Create and initialize DHCPv4 server
//!     let server = DhcpServer::new(config).await?;
//!
//!     // Run server event loop (blocks until shutdown signal)
//!     server.run().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # RFC Compliance
//!
//! This implementation adheres to the following RFCs:
//!
//! - **RFC 2131**: Dynamic Host Configuration Protocol (core protocol)
//! - **RFC 2132**: DHCP Options and BOOTP Vendor Extensions
//! - **RFC 1542**: Clarifications and Extensions for the Bootstrap Protocol
//! - **RFC 3046**: DHCP Relay Agent Information Option (option 82)
//! - **RFC 3397**: DNS Search List Option (option 119)
//! - **RFC 4039**: Rapid Commit Option (option 80)
//! - **RFC 4361**: Client Identifier Based on UUID (option 61)
//! - **RFC 4702**: DHCP Client FQDN Option (option 81)
//! - **PXE Specification v2.1**: PXE boot options and architecture types
//!
//! # Testing
//!
//! The module includes comprehensive test coverage:
//!
//! - **Unit Tests**: Embedded `#[cfg(test)]` modules in each submodule testing
//!   individual functions with edge cases
//! - **Integration Tests**: `tests/dhcp_tests.rs` verifying complete DHCP exchanges
//!   with mock network layer
//! - **Property-Based Tests**: `proptest` verification of RFC compliance invariants
//!   (e.g., all valid packets parse successfully, option encoding/decoding roundtrips)
//! - **Compatibility Tests**: Validates identical behavior to C implementation using
//!   same test vectors and packet captures

use std::io;
use std::time::Duration;

// ============================================================================
// Public Module Declarations
// ============================================================================

/// DHCPv4 protocol constants, message types, option codes, and wire-format structures.
///
/// Provides RFC 2131/2132-compliant definitions with type-safe enums and repr(C)
/// packet structures for binary compatibility.
pub mod protocol;

/// DHCP option parsing and building utilities.
///
/// Safe extraction and construction of DHCP options with automatic bounds checking,
/// UTF-8 validation for strings, and support for option overload and vendor-specific options.
pub mod options;

/// Ping-before-offer address conflict detection.
///
/// Async ICMP echo requests to verify IP availability before lease allocation,
/// with configurable timeout and result caching to prevent duplicate assignment.
pub mod ping;

/// DHCPv4 protocol message handlers.
///
/// State machine implementing RFC 2131 message processing for all message types:
/// DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, DECLINE, and INFORM.
pub mod handler;

/// DHCPv4 server runtime and async event loop.
///
/// Coordinates socket management, packet reception, protocol handling, lease
/// database updates, and DNS cache integration.
pub mod server;

// ============================================================================
// Public Re-exports: Protocol Module
// ============================================================================

// Message types from protocol module
pub use protocol::{
    MessageType,
    // Export individual message type variants for convenience
    MessageType::DHCPDISCOVER,
    MessageType::DHCPOFFER,
    MessageType::DHCPREQUEST,
    MessageType::DHCPDECLINE,
    MessageType::DHCPACK,
    MessageType::DHCPNAK,
    MessageType::DHCPRELEASE,
    MessageType::DHCPINFORM,
};

// Option codes from protocol module
pub use protocol::{
    OptionCode,
    SuboptionCode,
    PxeSuboption,
};

// Wire-format packet structure
pub use protocol::DhcpPacket;

// Port number constants
pub use protocol::{
    DHCP_SERVER_PORT,
    DHCP_CLIENT_PORT,
    PXE_PORT,
};

// Protocol constants
pub use protocol::{
    DHCP_COOKIE,
    MIN_PACKETSZ,
    DHCP_CHADDR_MAX,
    BOOTREQUEST,
    BOOTREPLY,
};

// ============================================================================
// Public Re-exports: Options Module
// ============================================================================

pub use options::{
    parse_options,
    build_options,
    OptionParser,
    OptionBuilder,
    OptionError,
};

// ============================================================================
// Public Re-exports: Ping Module
// ============================================================================

pub use ping::{
    icmp_ping,
    PingStatus,
    PingCache,
};

// ============================================================================
// Public Re-exports: Handler Module
// ============================================================================

pub use handler::{
    dhcp_reply,
    handle_discover,
    handle_request,
    handle_release,
    handle_decline,
    handle_inform,
    DhcpContext,
    ClientIdentifier,
};

// ============================================================================
// Public Re-exports: Server Module
// ============================================================================

pub use server::{
    DhcpServer,
    dhcp_init,
    ServerConfig,
};

// ============================================================================
// Type Aliases
// ============================================================================

/// Client identifier (DHCP option 61 data).
///
/// Variable-length byte array uniquely identifying a DHCP client. Format is
/// type byte (hardware type) followed by hardware address, or UUID for option 61.
pub type ClientId = Vec<u8>;

/// DHCP transaction identifier (xid field).
///
/// 32-bit random number chosen by client to match requests with responses.
/// Server echoes this value in all replies to the same client request.
pub type TransactionId = u32;

/// Lease duration.
///
/// Time duration for IP address lease validity. Typical values range from
/// 1 hour to 7 days. Uses `Duration` for overflow-safe arithmetic.
pub type LeaseTime = Duration;

// ============================================================================
// Module Constants
// ============================================================================

/// Default lease time in seconds (1 hour).
///
/// Used when client doesn't request specific lease time and configuration
/// doesn't specify a value. Matches C implementation default from `config.h`.
pub const DHCP_DEFAULT_LEASE: u32 = 3600;

/// DHCP packet processing timeout.
///
/// Maximum time allowed for DHCP request processing including lease allocation,
/// ping-before-offer, and response construction. Prevents indefinite blocking.
pub const DHCP_TIMEOUT: Duration = Duration::from_secs(60);

/// Ping-before-offer ICMP echo timeout.
///
/// Time to wait for ICMP echo reply before assuming address is available.
/// RFC 2131 recommends checking for address conflicts but doesn't specify timeout.
pub const PING_TIMEOUT: Duration = Duration::from_millis(500);

/// Minimum DHCPv4 packet size (300 bytes).
///
/// Packets shorter than this are padded with `OPTION_PAD` to work around
/// Linux in-kernel DHCP client bug. Matches `MIN_PACKETSZ` from protocol module.
pub const DHCP_MIN_PACKET_SIZE: usize = 300;

/// Maximum DHCPv4 packet size (576 bytes).
///
/// Maximum size of DHCP packet without fragmentation per RFC 2131 Section 2.
/// Clients may request larger sizes via `OPTION_MAXMESSAGE` (57), but default
/// is 576 bytes (minimum IPv4 datagram size).
pub const DHCP_MAX_PACKET_SIZE: usize = 576;

// ============================================================================
// Error Type
// ============================================================================

/// DHCPv4 module error type.
///
/// Encompasses all error conditions that can occur during DHCP operations,
/// from packet validation failures to lease allocation errors.
#[derive(Debug)]
pub enum DhcpError {
    /// Received packet smaller than minimum DHCPv4 packet size.
    ///
    /// Valid DHCP packets must be at least 236 bytes (fixed header) and
    /// typically padded to 300 bytes minimum.
    PacketTooSmall,

    /// Invalid or malformed DHCP option.
    ///
    /// Contains the option code that caused the error. Reasons include:
    /// - Option length extends beyond packet bounds
    /// - Invalid UTF-8 in string option
    /// - Wrong length for fixed-size option (e.g., IP address not 4 bytes)
    InvalidOption(OptionCode),

    /// ICMP ping-before-offer operation failed.
    ///
    /// Wraps the underlying I/O error from ICMP socket operations. Non-fatal:
    /// server may proceed with allocation if ping fails rather than refusing lease.
    PingFailed(io::Error),

    /// No IP address available for lease allocation.
    ///
    /// All addresses in applicable DHCP contexts are either already allocated,
    /// reserved for static hosts, or failed ping-before-offer check.
    LeaseUnavailable,

    /// Invalid DHCP magic cookie.
    ///
    /// Options field must start with 0x63825363 per RFC 2131 Section 3.
    /// Legacy BOOTP packets lack this cookie.
    InvalidCookie,

    /// Missing required DHCP option.
    ///
    /// Some message types require specific options (e.g., DHCPREQUEST requires
    /// either `OPTION_REQUESTED_IP` or `OPTION_SERVER_IDENTIFIER`).
    MissingRequiredOption(OptionCode),

    /// I/O error during socket operations.
    ///
    /// Wraps errors from UDP socket send/receive, file operations for lease
    /// database, or network interface enumeration.
    Io(io::Error),

    /// Configuration error.
    ///
    /// DHCP context configuration is invalid (e.g., range start > range end,
    /// netmask doesn't match range, overlapping contexts).
    ConfigError(String),
}

impl std::fmt::Display for DhcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhcpError::PacketTooSmall => {
                write!(f, "DHCP packet too small (minimum {} bytes)", DHCP_MIN_PACKET_SIZE)
            }
            DhcpError::InvalidOption(opt) => {
                write!(f, "Invalid DHCP option: {:?}", opt)
            }
            DhcpError::PingFailed(err) => {
                write!(f, "Ping-before-offer failed: {}", err)
            }
            DhcpError::LeaseUnavailable => {
                write!(f, "No IP address available for allocation")
            }
            DhcpError::InvalidCookie => {
                write!(f, "Invalid DHCP magic cookie (expected 0x{:08X})", DHCP_COOKIE)
            }
            DhcpError::MissingRequiredOption(opt) => {
                write!(f, "Missing required DHCP option: {:?}", opt)
            }
            DhcpError::Io(err) => {
                write!(f, "I/O error: {}", err)
            }
            DhcpError::ConfigError(msg) => {
                write!(f, "Configuration error: {}", msg)
            }
        }
    }
}

impl std::error::Error for DhcpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DhcpError::PingFailed(err) | DhcpError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for DhcpError {
    fn from(err: io::Error) -> Self {
        DhcpError::Io(err)
    }
}

impl From<OptionError> for DhcpError {
    fn from(err: OptionError) -> Self {
        match err {
            OptionError::InvalidOption { code, reason: _ } => DhcpError::InvalidOption(
                OptionCode::from_u8(code).unwrap_or(OptionCode::OPTION_PAD)
            ),
            _ => DhcpError::ConfigError(format!("Option error: {:?}", err)),
        }
    }
}

// ============================================================================
// Conditional Compilation for Optional Features
// ============================================================================

/// PXE boot support module (conditional compilation).
///
/// Enabled with `pxe` feature flag. Provides PXE-specific option handling,
/// architecture detection, and proxy DHCP mode for network booting.
#[cfg(feature = "pxe")]
pub mod pxe {
    //! PXE (Pre-boot Execution Environment) boot support.
    //!
    //! Handles PXE-specific DHCP options, architecture type detection,
    //! boot filename selection, and proxy DHCP operation on port 4011.

    pub use super::protocol::PxeSuboption;
    
    /// PXE client architecture types per PXE specification.
    #[repr(u16)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PxeArchitecture {
        /// Intel x86 BIOS (0)
        X86Bios = 0,
        /// Intel x86 UEFI (6)
        X86Uefi = 6,
        /// Intel x64 UEFI (7)
        X64Uefi = 7,
        /// EFI Itanium (2)
        EfiItanium = 2,
        /// ARM 32-bit UEFI (10)
        Arm32Uefi = 10,
        /// ARM 64-bit UEFI (11)
        Arm64Uefi = 11,
    }
}

/// Rapid commit support (conditional compilation).
///
/// Enabled with `rapid-commit` feature flag. Allows 2-message DHCP exchange
/// (DISCOVER with rapid-commit -> ACK with rapid-commit) per RFC 4039.
#[cfg(feature = "rapid-commit")]
pub use protocol::OptionCode::OPTION_RAPID_COMMIT;

// ============================================================================
// Module Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify constants match C implementation values
        assert_eq!(DHCP_SERVER_PORT, 67);
        assert_eq!(DHCP_CLIENT_PORT, 68);
        assert_eq!(PXE_PORT, 4011);
        assert_eq!(DHCP_COOKIE, 0x6382_5363);
        assert_eq!(BOOTREQUEST, 1);
        assert_eq!(BOOTREPLY, 2);
        assert_eq!(DHCP_DEFAULT_LEASE, 3600);
        assert_eq!(DHCP_MIN_PACKET_SIZE, 300);
        assert_eq!(DHCP_MAX_PACKET_SIZE, 576);
    }

    #[test]
    fn test_durations() {
        assert_eq!(DHCP_TIMEOUT.as_secs(), 60);
        assert_eq!(PING_TIMEOUT.as_millis(), 500);
    }

    #[test]
    fn test_message_type_enum() {
        // Verify message types can be created and converted
        assert_eq!(MessageType::DHCPDISCOVER as u8, 1);
        assert_eq!(MessageType::DHCPOFFER as u8, 2);
        assert_eq!(MessageType::DHCPREQUEST as u8, 3);
        assert_eq!(MessageType::DHCPDECLINE as u8, 4);
        assert_eq!(MessageType::DHCPACK as u8, 5);
        assert_eq!(MessageType::DHCPNAK as u8, 6);
        assert_eq!(MessageType::DHCPRELEASE as u8, 7);
        assert_eq!(MessageType::DHCPINFORM as u8, 8);
    }

    #[test]
    fn test_error_display() {
        let err = DhcpError::PacketTooSmall;
        assert!(err.to_string().contains("too small"));

        let err = DhcpError::LeaseUnavailable;
        assert!(err.to_string().contains("No IP address"));

        let err = DhcpError::InvalidCookie;
        assert!(err.to_string().contains("magic cookie"));
    }

    #[test]
    fn test_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "test error");
        let dhcp_err: DhcpError = io_err.into();
        assert!(matches!(dhcp_err, DhcpError::Io(_)));
    }
}
