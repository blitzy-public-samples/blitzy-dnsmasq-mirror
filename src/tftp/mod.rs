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

//! TFTP (Trivial File Transfer Protocol) Subsystem
//!
//! This module implements a TFTP server for network boot and file transfer,
//! providing PXE (Pre-boot Execution Environment) and UEFI HTTP boot support.
//!
//! # Features
//!
//! - **RFC 1350**: TFTP Protocol (Read Request, Data, Acknowledgment, Error)
//! - **RFC 2347**: TFTP Option Extension (blksize, tsize, timeout)
//! - **RFC 2348**: TFTP Blocksize Option (512 to 65464 bytes)
//! - **RFC 2349**: TFTP Timeout Interval and Transfer Size Options
//! - **Netascii mode** with CR-LF translation
//! - **Secure mode** with file ownership verification
//! - **Multi-port and single-port** operation modes
//! - **Concurrent multi-client** serving with file handle sharing
//! - **Path traversal prevention** for security
//! - **Per-interface TFTP** root directories
//! - **DHCP integration** for MAC-based root selection
//!
//! # Usage
//!
//! ```rust,no_run
//! use dnsmasq::tftp::{TftpServer, TftpConfig};
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = TftpConfig {
//!         root_dir: PathBuf::from("/var/tftp"),
//!         secure_mode: true,
//!         single_port: false,
//!         ..Default::default()
//!     };
//!     
//!     let mut server = TftpServer::new(config);
//!     server.bind()?;
//!     server.run().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Security Considerations
//!
//! - Always enable `secure_mode` in production to require file ownership
//! - Use path traversal prevention (enabled by default)
//! - Run as non-root user after binding privileged port
//! - Limit served directory tree with proper filesystem permissions
//! - Consider firewall rules to restrict TFTP access to trusted networks
//!
//! # Related Configuration Options
//!
//! From dnsmasq.conf:
//! - `enable-tftp`: Enable TFTP server
//! - `tftp-root`: Set TFTP root directory
//! - `tftp-secure`: Enable secure mode (file ownership check)
//! - `tftp-single-port`: Use single port 69 for all transfers
//! - `tftp-port-range`: Specify ephemeral port range for transfers
//! - `tftp-unique-root`: Use client IP/MAC for subdirectory selection
//! - `tftp-lowercase`: Convert filenames to lowercase
//! - `tftp-no-blocksize`: Disable blocksize negotiation
//!
//! # Integration with DHCP
//!
//! TFTP server integrates with DHCP via options 66 (TFTP server name) and 67 (boot filename).
//! When 'dhcp' feature is enabled, supports MAC address lookup for unique root directory selection.
//!
//! # Integration with Network Layer
//!
//! Uses network::socket module for UDP socket creation and packet transmission.
//! Supports multi-homed configurations with interface-specific binding.
//!
//! # Platform-Specific Behavior
//!
//! - **Linux**: Uses IP_PKTINFO for interface detection, supports SO_BINDTODEVICE
//! - **BSD**: Uses IP_RECVDSTADDR and IP_RECVIF for packet routing
//! - **Solaris**: Similar to BSD with platform-specific control messages
//! - **macOS**: Uses IP_RECVIF for interface-aware serving
//!
//! # Cargo Features
//!
//! - `tftp`: Enable TFTP server (default: included in 'default' features)
//! - `dhcp`: Enable DHCP integration for MAC-based root selection
//! - `scripts`: Enable post-transfer script execution
//!
//! # RFC Compliance Matrix
//!
//! | RFC | Feature | Implementation |
//! |-----|---------|----------------|
//! | 1350 | TFTP Protocol | ✓ Complete |
//! | 2347 | Option Extension | ✓ Complete |
//! | 2348 | Blocksize Option | ✓ Complete |
//! | 2349 | Timeout/Tsize Options | ✓ Complete |
//!
//! ## Known Deviations
//!
//! - WRQ (Write Request) not supported for security reasons
//! - Mail mode not supported (obsolete per RFC 1350)
//! - Maximum blocksize limited to 65464 bytes (MTU consideration)
//!
//! # Migration from C Implementation
//!
//! This Rust implementation maintains protocol compatibility with the C version
//! but uses async I/O and Tokio runtime. Key differences:
//!
//! - Async functions replace blocking I/O
//! - `Arc<TftpFile>` replaces manual reference counting
//! - `HashMap<SocketAddr, Transfer>` replaces linked list
//! - Drop trait replaces manual `free_transfer()` calls
//! - Result types replace errno and return codes
//! - Type-safe enums replace `#define` constants
//!
//! # C Source Reference
//!
//! Translates from: `src/tftp.c` (1600+ lines)

use thiserror::Error;

// Module declarations
pub mod protocol;
pub mod server;
pub mod transfer;

// Re-export protocol types
pub use protocol::{ProtocolError, TftpErrorCode, TftpOpcode, TftpPacket, TransferMode};

// Re-export transfer types
pub use transfer::{TftpFile, Transfer, TransferOptions};

// Re-export server types
pub use server::{ServerError, TftpConfig, TftpServer, handle_request};

/// Unified TFTP error type wrapping all submodule errors
///
/// This error type consolidates protocol parsing errors, transfer operation errors,
/// and server-level errors into a single enumeration, enabling comprehensive error
/// handling at the module boundary while maintaining type safety.
///
/// # C Source Reference
///
/// Replaces C's errno-based error handling and return codes with Rust's type-safe Result pattern.
/// Corresponds to various error returns throughout tftp.c (lines 116-840).
#[derive(Error, Debug)]
pub enum TftpError {
    /// Protocol parsing or validation error
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// Transfer state or operation error
    #[error("Transfer error: {0}")]
    Transfer(#[from] transfer::TransferError),

    /// Server-level error (binding, permissions, configuration)
    #[error("Server error: {0}")]
    Server(#[from] ServerError),

    /// I/O error during file or network operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenient Result type alias for TFTP operations
///
/// Simplifies function signatures throughout the TFTP subsystem by providing
/// a default error type of `TftpError`.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::tftp::Result;
///
/// fn parse_packet(data: &[u8]) -> Result<()> {
///     // Function body
///     Ok(())
/// }
/// ```
pub type Result<T> = std::result::Result<T, TftpError>;

/// TFTP block number type (16-bit unsigned integer)
///
/// Represents the block sequence number in DATA and ACK packets per RFC 1350.
/// Block numbers start at 1 and wrap around to 0 after 65535, allowing
/// transfers larger than 32 MB with standard 512-byte blocks.
///
/// # C Source Reference
///
/// Corresponds to `block` field in `struct tftp_transfer` (src/tftp.c line 768)
pub type BlockNumber = u16;

/// TFTP block size type (16-bit unsigned integer)
///
/// Represents the negotiated block size for data transfers per RFC 2348.
/// Valid range is 8 to 65464 bytes, with 512 bytes as the default.
/// Larger block sizes improve transfer efficiency but require careful MTU consideration.
///
/// # C Source Reference
///
/// Corresponds to `blocksize` field in `struct tftp_transfer` (src/tftp.c line 769)
pub type Blocksize = u16;

/// Testing utilities available in test builds
///
/// Provides mock implementations and test helpers for unit and integration testing
/// of TFTP functionality without requiring actual network operations or file access.
#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    /// Create a test TFTP configuration with default values
    pub fn test_config() -> TftpConfig {
        TftpConfig {
            root_dir: PathBuf::from("/tmp/tftp-test"),
            secure_mode: false,
            single_port: true,
            max_blocksize: 1468,
            port_range: None,
            lowercase_filenames: false,
            unique_root_mode: None,
            mtu: None,
            no_blocksize: false,
        }
    }

    /// Create a test socket address for client simulation
    pub fn test_client_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 50000)
    }

    /// Create a test request packet with default parameters
    pub fn test_request_packet() -> protocol::RequestPacket {
        protocol::RequestPacket::new(
            TftpOpcode::RRQ,
            "pxelinux.0".to_string(),
            TransferMode::Octet,
        )
    }
}
