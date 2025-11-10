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

//! Auxiliary network services subsystem
//!
//! # Purpose
//!
//! This module provides the services subsystem for dnsmasq, managing auxiliary network
//! services that complement the core DNS and DHCP functionality. Currently implements
//! the TFTP (Trivial File Transfer Protocol) server for PXE boot support and network
//! file transfer capabilities.
//!
//! # Architecture
//!
//! The services subsystem establishes clear API boundaries between auxiliary services
//! and other subsystems (core, network, config), maintaining separation of concerns
//! while providing memory-safe implementations of network protocols. This design allows
//! for future extension with additional services while preserving modularity.
//!
//! # Memory Safety Transformation
//!
//! This module root replaces C's header-based inclusion system (`#include "tftp.c"`)
//! with Rust's explicit module system, providing:
//!
//! - **Module Isolation:** Each service is a separate module with defined public API
//! - **Conditional Compilation:** Feature flags control service availability at compile time
//! - **Safe Re-exports:** Type-safe public API through explicit re-export declarations
//! - **No Header Guards:** Rust's module system prevents duplicate definitions automatically
//!
//! # Available Services
//!
//! ## TFTP Server (RFC 1350)
//!
//! Enabled with `tftp` feature flag (default: enabled)
//!
//! Provides lightweight file transfer service for:
//! - PXE (Pre-boot Execution Environment) network booting
//! - UEFI HTTP boot support
//! - Firmware downloads for embedded devices
//! - Configuration file distribution
//!
//! Key features:
//! - RFC 1350 (TFTP) base protocol
//! - RFC 2347 (Option Extension)
//! - RFC 2348 (Block size negotiation)
//! - RFC 2349 (Transfer size and timeout options)
//! - Async I/O with tokio for high concurrency
//! - Path traversal prevention and secure mode
//! - File descriptor sharing for mass boot scenarios
//!
//! See [`tftp`] module for detailed documentation.
//!
//! # Usage Example
//!
//! ```ignore
//! use dnsmasq::services::{TftpServer, TftpConfig};
//! use dnsmasq::core::daemon::Daemon;
//! use std::sync::Arc;
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure TFTP service
//!     let tftp_config = TftpConfig {
//!         tftp_root: Some(PathBuf::from("/var/tftp")),
//!         secure_mode: true,
//!         single_port: false,
//!         mtu: 1500,
//!         port_range: None,
//!         ..Default::default()
//!     };
//!     
//!     // Initialize daemon and logger (setup not shown)
//!     let daemon = Arc::new(/* Daemon initialization */);
//!     let logger = Arc::new(/* Logger initialization */);
//!     
//!     // Create and run TFTP server
//!     #[cfg(feature = "tftp")]
//!     {
//!         let tftp_server = TftpServer::new(
//!             tftp_config,
//!             daemon,
//!             logger,
//!             #[cfg(feature = "script")]
//!             None, // Optional helper handle
//!         ).await?;
//!         
//!         tftp_server.run().await?;
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Feature Flags
//!
//! - `tftp` - Enable TFTP server (default: enabled, matches C's HAVE_TFTP)
//! - `script` - Enable external script support for TFTP events (requires helper process)
//! - `dump` - Enable packet dumping for debugging (requires dump feature)
//!
//! # Original C Implementation
//!
//! This module replaces manual header inclusion in C implementation. There is no direct
//! C equivalent - C used `#include "tftp.c"` in the main source file. The Rust module
//! system provides superior organization with:
//!
//! - Explicit dependency declaration
//! - Compile-time feature checking
//! - Automatic symbol visibility management
//! - Prevention of symbol conflicts
//!
//! C implementation: src/tftp.c (~1500 lines)
//! Rust implementation: src_rust/services/tftp.rs (~1200 lines, more structured)

/// TFTP server module providing RFC 1350 compliant implementation with PXE boot support
///
/// This module implements the complete TFTP protocol stack including:
/// - Basic TFTP operations (RRQ, DATA, ACK, ERROR)
/// - Option negotiation (block size, transfer size)
/// - Security features (path validation, secure mode)
/// - Async I/O for concurrent transfers
/// - Timeout and retransmission handling
///
/// See module documentation for usage examples and protocol details.
#[cfg(feature = "tftp")]
pub mod tftp;

// Re-export public TFTP types for convenient access
#[cfg(feature = "tftp")]
pub use tftp::{TftpServer, TftpError};

// Re-export TftpConfig from config module for API consistency
// Users can access configuration types directly from services module
#[cfg(feature = "tftp")]
pub use crate::config::types::TftpConfig;
