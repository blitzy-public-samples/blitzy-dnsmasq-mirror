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

//! # DHCP Subsystem Module
//!
//! This module provides unified, memory-safe implementations of DHCPv4 (RFC 2131/2132)
//! and DHCPv6 (RFC 3315/3633) server functionality, replacing the C implementations
//! in `src/dhcp.c`, `src/dhcp6.c`, `src/rfc2131.c`, `src/rfc3315.c`, `src/dhcp-common.c`,
//! and `src/lease.c`.
//!
//! ## Purpose
//!
//! The DHCP subsystem enables automatic network configuration for IPv4 and IPv6 clients
//! by implementing the Dynamic Host Configuration Protocol. It provides:
//!
//! - **Address Allocation**: Dynamic IP address assignment from configured pools
//! - **Lease Management**: Persistent tracking of address assignments with expiry
//! - **Configuration Distribution**: Network parameters (DNS, gateway, NTP, etc.)
//! - **Static Reservations**: Fixed address assignments based on client identifiers
//! - **Relay Agent Support**: Multi-subnet DHCP via relay forwarding
//! - **DNS Integration**: Dynamic hostname registration in DNS cache
//! - **External Script Hooks**: Lease event notifications for custom integrations
//!
//! ## Architecture
//!
//! The module is organized into four main submodules:
//!
//! ### [`common`]
//!
//! Shared utilities used by both DHCPv4 and DHCPv6 implementations:
//! - Option parsing and encoding with safe bounds checking
//! - Client configuration matching (by MAC, client-id, hostname)
//! - Tag-based conditional configuration (vendor class, user class, etc.)
//! - Packet validation and logging utilities
//! - Action code constants for external script invocation
//!
//! ### [`lease`]
//!
//! Lease database management for persistent address tracking:
//! - Atomic file updates using write-temp-rename strategy
//! - In-memory lease database with HashMap-based lookups
//! - Lease allocation, renewal, and expiration handling
//! - DNS cache synchronization for dynamic hostname resolution
//! - Backward-compatible lease file format (one lease per line)
//!
//! ### [`v4`]
//!
//! Complete DHCPv4 server implementation per RFC 2131 and RFC 2132:
//! - Protocol message types: DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, DECLINE, INFORM
//! - BOOTP compatibility for legacy clients
//! - PXE (Pre-boot Execution Environment) support
//! - Ping-before-offer conflict detection
//! - DHCP option parsing and building
//! - Relay agent support with option 82 handling
//!
//! ### [`v6`]
//!
//! Complete DHCPv6 server implementation per RFC 3315, RFC 3633, RFC 4361:
//! - Protocol message types: SOLICIT, ADVERTISE, REQUEST, REPLY, RENEW, REBIND, RELEASE, DECLINE
//! - Stateful address assignment (IA_NA, IA_TA) with T1/T2 renewal timers
//! - Stateless configuration (INFORMATION-REQUEST) for DNS/NTP
//! - Prefix Delegation (IA_PD) for routing scenarios
//! - DUID (DHCP Unique Identifier) generation and parsing
//! - Relay agent support with RELAY-FORW/RELAY-REPL messages
//! - Integration with Router Advertisement (radv) for managed/other flags
//!
//! ## Memory Safety Improvements Over C Implementation
//!
//! This Rust implementation eliminates entire classes of vulnerabilities present in the
//! C version through Rust's ownership system and type safety:
//!
//! ### Buffer Overflow Prevention
//! - **C**: Manual bounds checking with `strcpy()`, `sprintf()`, pointer arithmetic
//! - **Rust**: Automatic bounds checking via slice types, `String`, and `Vec<T>`
//! - **Eliminated**: Buffer overflow in option parsing, packet building, hostname handling
//!
//! ### Use-After-Free Prevention
//! - **C**: Manual memory management with `malloc()`/`free()`, linked lists
//! - **Rust**: Ownership system with RAII, automatic deallocation via Drop trait
//! - **Eliminated**: Dangling pointers in lease database, option chains, relay forwarding
//!
//! ### Null Pointer Dereference Prevention
//! - **C**: Defensive null checks before pointer dereferences
//! - **Rust**: Option<T> type eliminates null pointers entirely
//! - **Eliminated**: Null pointer bugs in context lookups, lease searches, config matching
//!
//! ### Type Safety Enforcement
//! - **C**: Void pointers, union types, unchecked casts
//! - **Rust**: Strong static typing with enum variants and exhaustive matching
//! - **Eliminated**: Type confusion in packet structures, option values, address types
//!
//! ### Concurrent Access Safety
//! - **C**: Single-threaded poll() loop (no concurrency safety)
//! - **Rust**: Async/await with `Arc<RwLock<T>>` for shared mutable state
//! - **Benefit**: Future-proof for multi-threaded operation with zero data races
//!
//! ### Error Handling Guarantees
//! - **C**: errno-based errors with unchecked return values
//! - **Rust**: Result<T, E> types with ? operator forcing error handling
//! - **Benefit**: All errors must be explicitly handled or propagated
//!
//! ## DHCPv4 vs DHCPv6 Key Differences
//!
//! While both protocols serve similar purposes, they differ significantly in design:
//!
//! | Aspect | DHCPv4 (RFC 2131) | DHCPv6 (RFC 3315) |
//! |--------|-------------------|-------------------|
//! | **Packet Format** | Fixed 236-byte header + options | Variable TLV (Type-Length-Value) encoding |
//! | **Client ID** | MAC address (chaddr) + optional client-id | DUID (DHCP Unique Identifier) mandatory |
//! | **Message Flow** | 4-message: DISCOVER/OFFER/REQUEST/ACK | 4-message: SOLICIT/ADVERTISE/REQUEST/REPLY |
//! | **Broadcast** | Uses broadcast for discovery | Uses multicast (FF02::1:2) |
//! | **Address Types** | Single IPv4 address | IA_NA (non-temporary), IA_TA (temporary), IA_PD (prefix) |
//! | **Renewal** | Implicit T1/T2 from lease time | Explicit T1/T2 values per IA |
//! | **Relay Agent** | Option 82 (Relay Agent Information) | RELAY-FORW/RELAY-REPL message types |
//! | **Configuration** | Always includes address | Can be stateless (no address allocation) |
//! | **Status Reporting** | NAK message for errors | Status codes in options (Success, NoAddrsAvail, etc.) |
//!
//! ## Configuration Compatibility
//!
//! This Rust implementation maintains 100% backward compatibility with existing dnsmasq
//! configuration files. All dhcp-range, dhcp-host, dhcp-option, and related configuration
//! directives are parsed identically to the C version. The lease file format is also
//! backward compatible, allowing external tools to continue parsing lease information.
//!
//! ## Performance Characteristics
//!
//! ### Target Performance (matching or exceeding C implementation)
//! - **DHCPv4 Throughput**: >5,000 DISCOVER-ACK cycles per second
//! - **DHCPv6 Throughput**: >5,000 SOLICIT-REPLY cycles per second
//! - **Lease Database Lookups**: O(1) average time via HashMap (vs O(n) linked list in C)
//! - **Memory Footprint**: Within 20% of C implementation baseline
//! - **Startup Time**: <100ms additional latency for lease database loading
//!
//! ### Optimization Strategies
//! - **Zero-copy parsing** where possible using slice references
//! - **Pre-allocated buffers** for packet building to reduce allocations
//! - **Cached ping results** with 90-second TTL to avoid redundant ICMP probes
//! - **Batch DNS updates** to minimize cache lock contention
//! - **Async I/O** for non-blocking file operations and network I/O
//!
//! ## Lease File Persistence Strategy
//!
//! The lease database is persisted using an atomic write-temp-rename strategy to prevent
//! corruption from crashes or power failures:
//!
//! 1. Write complete lease database to temporary file (`<leasefile>.tmp`)
//! 2. Call `fsync()` to ensure data is flushed to disk
//! 3. Atomically rename temporary file to final name (`<leasefile>`)
//! 4. Only update if changes detected (lease added/removed/modified)
//!
//! This guarantees that the lease file is always in a consistent state, even if dnsmasq
//! is terminated abruptly during write operations.
//!
//! ## Integration Points
//!
//! ### DNS Cache Integration
//! - Lease allocations trigger DNS cache updates for dynamic hostname resolution
//! - PTR records created for reverse DNS lookups
//! - Hostname conflicts handled via sequential numbering (host-2, host-3, etc.)
//!
//! ### Network Layer Integration
//! - Receives DHCP packets via `network::sockets` UDP socket infrastructure
//! - Uses platform-specific packet transmission (IP_PKTINFO on Linux, IP_RECVIF on BSD)
//! - Integrates with ARP table for conflict detection on Linux
//!
//! ### External Script Execution
//! - Invokes dhcp-script on lease events: add, del, old (renewal), old-hostname
//! - Script receives environment variables: DNSMASQ_LEASE_EXPIRES, DNSMASQ_CLIENT_ID, etc.
//! - Async execution via `tokio::process::Command` to avoid blocking event loop
//!
//! ### D-Bus/ubus Control Interfaces
//! - Exposes `ClearCache`, `GetLeases`, `SetDhcpHost` methods
//! - Used by OpenWrt luci web interface and NetworkManager
//!
//! ### Router Advertisement Coordination (DHCPv6)
//! - Reads managed/other flags from RA to determine stateful vs stateless mode
//! - Synchronizes prefix information for IA_PD allocations
//!
//! ## RFC Compliance
//!
//! This implementation strictly follows IETF RFCs for protocol correctness:
//!
//! ### DHCPv4
//! - **RFC 2131**: Dynamic Host Configuration Protocol (MUST implement)
//! - **RFC 2132**: DHCP Options and BOOTP Vendor Extensions (MUST implement)
//! - **RFC 3011**: IPv4 Subnet Selection Option (SHOULD implement)
//! - **RFC 3527**: Link Selection sub-option (SHOULD implement)
//! - **RFC 4039**: Rapid Commit Option (MAY implement)
//!
//! ### DHCPv6
//! - **RFC 3315**: Dynamic Host Configuration Protocol for IPv6 (MUST implement)
//! - **RFC 3633**: IPv6 Prefix Delegation (SHOULD implement for routing)
//! - **RFC 4361**: Node-specific Identifiers for DHCPv4 and DHCPv6
//! - **RFC 3646**: DNS Configuration Options (SHOULD implement)
//! - **RFC 5908**: NTP Server Option (SHOULD implement)
//! - **RFC 6939**: Client Link-Layer Address Option (MAY implement)
//!
//! ## Testing Strategy
//!
//! Comprehensive testing ensures protocol correctness and behavioral equivalence with C:
//!
//! - **Unit tests**: Individual function correctness (option parsing, allocation logic)
//! - **Integration tests**: Full message exchange flows (DISCOVER-ACK, SOLICIT-REPLY)
//! - **Property-based tests** (via proptest): RFC invariant validation
//! - **Compatibility tests**: Verify identical behavior to C implementation
//! - **Fuzzing**: AFL/libFuzzer for packet parser robustness
//! - **Interoperability tests**: Against real DHCP clients (ISC dhclient, systemd-networkd)
//!
//! ## Conditional Compilation
//!
//! The DHCP subsystem respects Cargo feature flags matching C's conditional compilation:
//!
//! - `dhcp`: Enable DHCPv4 server (default: enabled)
//! - `dhcp6`: Enable DHCPv6 server (default: enabled, requires dhcp feature)
//! - `script`: Enable external script execution (default: enabled)
//! - `dbus`: Enable D-Bus control interface (default: optional)
//! - `lua`: Enable Lua script callbacks (default: optional)
//!
//! ## Original C Files Replaced
//!
//! This module consolidates functionality from multiple C source files:
//! - `src/dhcp.c` → `v4::server` (DHCPv4 core logic)
//! - `src/rfc2131.c` → `v4::handler` (DHCPv4 protocol implementation)
//! - `src/dhcp6.c` → `v6::server` (DHCPv6 core logic)
//! - `src/rfc3315.c` → `v6::handler` (DHCPv6 protocol implementation)
//! - `src/dhcp-common.c` → `common` (shared utilities)
//! - `src/lease.c` → `lease` (lease database management)
//! - `src/dhcp-protocol.h` → `v4::protocol` (DHCPv4 constants)
//! - `src/dhcp6-protocol.h` → `v6::protocol` (DHCPv6 constants)
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use dnsmasq::dhcp::{DhcpError, lease_init};
//! use dnsmasq::dhcp::v4::{DhcpServer, dhcp_init};
//! use dnsmasq::dhcp::v6::{Dhcp6Server};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), DhcpError> {
//!     // Initialize lease database from file
//!     let lease_manager = lease_init("/var/lib/dnsmasq/dnsmasq.leases").await?;
//!     
//!     // Initialize DHCPv4 server
//!     let dhcp4_server = dhcp_init(&daemon_opts, lease_manager.clone()).await?;
//!     
//!     // Initialize DHCPv6 server
//!     let dhcp6_server = Dhcp6Server::new(&daemon_opts, lease_manager).await?;
//!     
//!     // Run servers concurrently
//!     tokio::select! {
//!         res = dhcp4_server.run() => res?,
//!         res = dhcp6_server.run() => res?,
//!     }
//!     
//!     Ok(())
//! }
//! ```

// ========== Standard Library Imports ==========

use std::error::Error as StdError;
use std::fmt::{self, Debug, Display};
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

// ========== Submodule Declarations ==========

/// Shared DHCPv4/DHCPv6 utilities
///
/// Provides option parsing, client configuration matching, tag-based filtering,
/// and packet validation functions used by both DHCPv4 and DHCPv6 servers.
///
/// Original C files: `src/dhcp-common.c`
pub mod common;

/// Lease database management
///
/// Implements persistent lease storage with atomic file updates, lease allocation,
/// expiry tracking, and DNS cache synchronization for both DHCPv4 and DHCPv6.
///
/// Original C file: `src/lease.c`
pub mod lease;

/// DHCPv4 server implementation
///
/// Complete RFC 2131/2132 DHCPv4 server with BOOTP compatibility, PXE support,
/// ping-before-offer conflict detection, and relay agent handling.
///
/// Original C files: `src/dhcp.c`, `src/rfc2131.c`, `src/dhcp-protocol.h`
#[cfg(feature = "dhcp")]
pub mod v4;

/// DHCPv6 server implementation
///
/// Complete RFC 3315/3633 DHCPv6 server with stateful/stateless configuration,
/// prefix delegation, DUID handling, and relay agent support.
///
/// Original C files: `src/dhcp6.c`, `src/rfc3315.c`, `src/dhcp6-protocol.h`
#[cfg(feature = "dhcp6")]
pub mod v6;

// ========== Public Re-exports ==========

// Re-export key types from submodules for convenient external access

/// Re-export DhcpLease type
///
/// Individual DHCP lease record with client ID, hardware address, IP address,
/// expiry time, and associated metadata. Used by both DHCPv4 and DHCPv6.
pub use lease::DhcpLease;

/// Re-export lease initialization function
///
/// Loads existing leases from file at daemon startup and initializes the
/// in-memory lease database.
pub use lease::lease_init;

/// Re-export lease lookup function
///
/// Finds a lease by client identifier (DHCPv4 client-id or DHCPv6 DUID).
pub use lease::lease_find_by_client;

/// Re-export lease file update function
///
/// Atomically writes the lease database to disk using write-temp-rename strategy.
pub use lease::lease_update_file;

/// Re-export action code for adding leases
///
/// Used when invoking external DHCP scripts with "add" parameter.
pub use common::ACTION_ADD;

/// Re-export action code for deleting leases
///
/// Used when invoking external DHCP scripts with "del" parameter.
pub use common::ACTION_DEL;

/// Re-export action code for old lease update
///
/// Used when renewing an existing lease with same client.
pub use common::ACTION_OLD;

/// Re-export action code for TFTP transfers
///
/// Used when invoking TFTP-related scripts.
pub use common::ACTION_TFTP;

/// Re-export action code for ARP operations
///
/// Used when managing ARP table entries for DHCP clients.
pub use common::ACTION_ARP;

/// Re-export maximum hardware address length constant
///
/// Maximum size of hardware address (chaddr field) in DHCPv4 packets (16 bytes per RFC 2131).
pub use common::DHCP_CHADDR_MAX;

/// Re-export DHCPv6 temporary address lease type
///
/// Identifies DHCPv6 temporary addresses (IA_TA) with short lifetimes for privacy.
pub use common::LEASE_TA;

/// Re-export DHCPv6 non-temporary address lease type
///
/// Identifies DHCPv6 standard addresses (IA_NA) with normal lifetimes.
pub use common::LEASE_NA;

// ========== Module-Level Constants ==========

/// Default DHCP lease time (1 hour)
///
/// Used when no explicit lease time is configured. RFC 2131 recommends at least 1 hour
/// to avoid excessive DHCP traffic. Many networks use 24 hours (86400 seconds).
///
/// Original C: `DHCP_LEASE_TIME` in `config.h`
pub const DHCP_LEASE_DEFAULT: Duration = Duration::from_secs(3600);

/// DHCP operation timeout (10 seconds)
///
/// Maximum time to wait for DHCP operations like ping-before-offer ICMP probes,
/// external script execution, and DNS cache updates.
///
/// Original C: `DHCP_TIMEOUT` in `config.h`
pub const DHCP_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum DHCP packet size (1500 bytes)
///
/// Maximum size for DHCPv4 and DHCPv6 packets. DHCPv4 uses 576 bytes minimum
/// (RFC 2131), but modern networks support 1500 bytes (Ethernet MTU). DHCPv6
/// requires at least 1280 bytes (IPv6 minimum MTU).
///
/// Original C: `DHCP_PACKET_MAX` in `config.h`
pub const DHCP_PACKET_MAX: usize = 1500;

// ========== Error Types ==========

/// DHCP subsystem error type
///
/// Comprehensive error enum covering all failure modes in DHCPv4 and DHCPv6 operations.
/// Implements `std::error::Error` for integration with Rust's error handling ecosystem.
///
/// # Error Categories
///
/// - **Protocol Errors**: Invalid packets, malformed options, unsupported message types
/// - **Allocation Errors**: No available addresses, address conflicts, out of range
/// - **Client Errors**: Missing required fields, mismatched identifiers
/// - **Resource Errors**: File I/O failures, lease database corruption
/// - **Network Errors**: Socket failures, ping timeout, relay forwarding errors
///
/// # Example
///
/// ```rust
/// use dnsmasq::dhcp::DhcpError;
/// use std::net::Ipv4Addr;
///
/// fn allocate_address() -> Result<Ipv4Addr, DhcpError> {
///     // Simulate no addresses available
///     Err(DhcpError::NoAddressAvailable {
///         client_id: vec![0x01, 0x02, 0x03],
///         reason: "All addresses in range exhausted".to_string(),
///     })
/// }
/// ```
#[derive(Debug)]
pub enum DhcpError {
    /// DHCP packet is too small to contain valid header
    ///
    /// DHCPv4 requires minimum 236 bytes (fixed header), DHCPv6 requires
    /// minimum 4 bytes (message type + transaction ID).
    PacketTooSmall {
        /// Actual packet size received
        received: usize,
        /// Minimum required size for this packet type
        required: usize,
    },

    /// Invalid DHCP option encountered during parsing
    ///
    /// Option may have invalid length, malformed value, or violate RFC constraints
    /// (e.g., string options with embedded NULs, IP address options with wrong length).
    InvalidOption {
        /// Option code (e.g., 53 for Message Type)
        option_code: u8,
        /// Human-readable error description
        reason: String,
    },

    /// Invalid or unsupported DHCP message type
    ///
    /// Packet contains unknown message type value or message type inappropriate
    /// for current protocol state (e.g., REQUEST without prior DISCOVER).
    InvalidMessageType {
        /// Message type value from option 53 (DHCPv4) or first byte (DHCPv6)
        message_type: u8,
    },

    /// Required client identifier is missing from packet
    ///
    /// DHCPv6 requires DUID in all messages (RFC 3315 Section 22.2).
    /// DHCPv4 requires client-id or chaddr for identification.
    ClientIdMissing {
        /// Protocol context ("DHCPv4" or "DHCPv6")
        protocol: String,
    },

    /// Server identifier in client message doesn't match our server ID
    ///
    /// Indicates message is intended for a different DHCP server (common in
    /// multi-server deployments). Server should silently discard the message.
    ServerIdMismatch {
        /// Server DUID/ID from client message
        client_sent: Vec<u8>,
        /// Our actual server DUID/ID
        expected: Vec<u8>,
    },

    /// No IP address available in any configured range for this client
    ///
    /// All addresses in matching ranges are allocated, reserved, or excluded.
    /// Server responds with NAK (DHCPv4) or NoAddrsAvail status (DHCPv6).
    NoAddressAvailable {
        /// Client identifier for logging
        client_id: Vec<u8>,
        /// Reason why allocation failed
        reason: String,
    },

    /// Client's requested address is not on any configured link (DHCPv6)
    ///
    /// Client requested address outside server's configured prefixes.
    /// Server responds with NotOnLink status code (RFC 3315).
    NotOnLink {
        /// Requested IPv6 address
        requested: Ipv6Addr,
    },

    /// Client must use multicast for this operation (DHCPv6)
    ///
    /// Client sent unicast message when multicast is required (e.g., SOLICIT, REBIND).
    /// Server responds with UseMulticast status code (RFC 3315 Section 18.2.1).
    UseMulticast,

    /// Server has no binding for client's IA (DHCPv6)
    ///
    /// Client requested renewal/rebind but server has no record of the lease.
    /// Server responds with NoBinding status code.
    NoBinding {
        /// Client DUID
        client_duid: Vec<u8>,
        /// Identity Association ID (IAID)
        iaid: u32,
    },

    /// Ping-before-offer ICMP probe failed or timed out
    ///
    /// Address conflict detected: target address responded to ICMP echo request,
    /// indicating another host is using the address.
    PingFailed {
        /// IPv4 address that failed ping check
        address: Ipv4Addr,
    },

    /// Requested lease is unavailable (reserved, static, or allocated)
    ///
    /// Client requested specific address but it's not available for allocation.
    LeaseUnavailable {
        /// IP address client requested
        address: std::net::IpAddr,
        /// Reason why lease is unavailable
        reason: String,
    },

    /// I/O error during file, socket, or network operation
    ///
    /// Wraps `std::io::Error` for file operations (lease database read/write),
    /// socket operations (packet send/receive), or external script execution.
    IoError {
        /// Underlying I/O error
        source: IoError,
        /// Context describing what operation failed
        context: String,
    },
}

// Implement Display trait for human-readable error messages
impl Display for DhcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpError::PacketTooSmall { received, required } => {
                write!(
                    f,
                    "DHCP packet too small: received {} bytes, required {} bytes minimum",
                    received, required
                )
            }
            DhcpError::InvalidOption {
                option_code,
                reason,
            } => {
                write!(f, "Invalid DHCP option {}: {}", option_code, reason)
            }
            DhcpError::InvalidMessageType { message_type } => {
                write!(f, "Invalid DHCP message type: {}", message_type)
            }
            DhcpError::ClientIdMissing { protocol } => {
                write!(f, "{} client identifier missing from packet", protocol)
            }
            DhcpError::ServerIdMismatch {
                client_sent,
                expected,
            } => {
                write!(
                    f,
                    "Server ID mismatch: client sent {:?}, expected {:?}",
                    client_sent, expected
                )
            }
            DhcpError::NoAddressAvailable { client_id, reason } => {
                write!(
                    f,
                    "No address available for client {:?}: {}",
                    client_id, reason
                )
            }
            DhcpError::NotOnLink { requested } => {
                write!(
                    f,
                    "Requested IPv6 address {} is not on any configured link",
                    requested
                )
            }
            DhcpError::UseMulticast => {
                write!(f, "Client must use multicast for this DHCPv6 operation")
            }
            DhcpError::NoBinding {
                client_duid,
                iaid,
            } => {
                write!(
                    f,
                    "No binding for client DUID {:?} IAID {}",
                    client_duid, iaid
                )
            }
            DhcpError::PingFailed { address } => {
                write!(
                    f,
                    "Ping-before-offer failed: address {} already in use",
                    address
                )
            }
            DhcpError::LeaseUnavailable { address, reason } => {
                write!(f, "Lease for {} unavailable: {}", address, reason)
            }
            DhcpError::IoError { source, context } => {
                write!(f, "I/O error during {}: {}", context, source)
            }
        }
    }
}

// Implement std::error::Error trait for error ecosystem integration
impl StdError for DhcpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            DhcpError::IoError { source, .. } => Some(source),
            _ => None,
        }
    }
}

// Implement From<IoError> for convenient ? operator usage
impl From<IoError> for DhcpError {
    fn from(err: IoError) -> Self {
        DhcpError::IoError {
            source: err,
            context: "unknown operation".to_string(),
        }
    }
}

// Helper function to create IoError variant with context
impl DhcpError {
    /// Create IoError variant with descriptive context
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::DhcpError;
    /// use std::io;
    ///
    /// fn read_lease_file() -> Result<Vec<u8>, DhcpError> {
    ///     std::fs::read("/var/lib/dnsmasq/dnsmasq.leases")
    ///         .map_err(|e| DhcpError::with_io_context(e, "reading lease file"))
    /// }
    /// ```
    pub fn with_io_context(err: IoError, context: impl Into<String>) -> Self {
        DhcpError::IoError {
            source: err,
            context: context.into(),
        }
    }
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_constants() {
        // Verify default lease time is 1 hour
        assert_eq!(DHCP_LEASE_DEFAULT, Duration::from_secs(3600));
        
        // Verify timeout is 10 seconds
        assert_eq!(DHCP_TIMEOUT, Duration::from_secs(10));
        
        // Verify packet max is 1500 bytes (Ethernet MTU)
        assert_eq!(DHCP_PACKET_MAX, 1500);
        
        // Verify DHCP_CHADDR_MAX is 16 bytes per RFC 2131
        assert_eq!(DHCP_CHADDR_MAX, 16);
    }

    #[test]
    fn test_action_constants() {
        // Verify action code string constants
        assert_eq!(ACTION_ADD, "add");
        assert_eq!(ACTION_DEL, "del");
        assert_eq!(ACTION_OLD, "old");
        assert_eq!(ACTION_TFTP, "tftp");
        assert_eq!(ACTION_ARP, "arp");
    }

    #[test]
    fn test_lease_type_constants() {
        // Verify DHCPv6 lease type constants
        assert_eq!(LEASE_TA, 1); // Temporary address
        assert_eq!(LEASE_NA, 2); // Non-temporary address
    }

    #[test]
    fn test_error_display() {
        // Test PacketTooSmall error formatting
        let err = DhcpError::PacketTooSmall {
            received: 100,
            required: 236,
        };
        assert!(err.to_string().contains("100 bytes"));
        assert!(err.to_string().contains("236 bytes"));

        // Test InvalidOption error formatting
        let err = DhcpError::InvalidOption {
            option_code: 53,
            reason: "invalid length".to_string(),
        };
        assert!(err.to_string().contains("option 53"));
        assert!(err.to_string().contains("invalid length"));

        // Test NoAddressAvailable error formatting
        let err = DhcpError::NoAddressAvailable {
            client_id: vec![0x01, 0x02, 0x03],
            reason: "range exhausted".to_string(),
        };
        assert!(err.to_string().contains("range exhausted"));
    }

    #[test]
    fn test_error_from_io_error() {
        // Test From<IoError> conversion
        let io_err = IoError::new(IoErrorKind::NotFound, "file not found");
        let dhcp_err: DhcpError = io_err.into();
        
        match dhcp_err {
            DhcpError::IoError { source, context } => {
                assert_eq!(source.kind(), IoErrorKind::NotFound);
                assert_eq!(context, "unknown operation");
            }
            _ => panic!("Expected IoError variant"),
        }
    }

    #[test]
    fn test_error_with_context() {
        // Test with_io_context helper
        let io_err = IoError::new(IoErrorKind::PermissionDenied, "access denied");
        let dhcp_err = DhcpError::with_io_context(io_err, "writing lease file");
        
        match dhcp_err {
            DhcpError::IoError { source, context } => {
                assert_eq!(source.kind(), IoErrorKind::PermissionDenied);
                assert_eq!(context, "writing lease file");
            }
            _ => panic!("Expected IoError variant"),
        }
    }

    #[test]
    fn test_error_implements_std_error() {
        // Verify DhcpError implements std::error::Error trait
        let err = DhcpError::PacketTooSmall {
            received: 10,
            required: 236,
        };
        
        // Should be able to treat as trait object
        let _: &dyn StdError = &err;
    }
}
