//! Auxiliary network services subsystem
//!
//! This module provides auxiliary network services in dnsmasq, currently containing
//! the TFTP (Trivial File Transfer Protocol) server implementation for PXE boot support
//! and network file transfer capabilities.
//!
//! The services subsystem establishes clear API boundaries between auxiliary services
//! and other subsystems (core, network, config), maintaining separation of concerns
//! while providing memory-safe implementations of network protocols.

/// TFTP server module providing RFC 1350 compliant implementation
#[cfg(feature = "tftp")]
pub mod tftp;

#[cfg(feature = "tftp")]
pub use tftp::{TftpServer, TftpError};
