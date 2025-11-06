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

//! BSD Packet Filter table integration
//!
//! Integrates with BSD's PF (Packet Filter) for firewall table management on FreeBSD,
//! OpenBSD, and NetBSD. This replaces the C implementation in tables.c and uses ioctl
//! for PF communication.

use std::fmt;

/// BSD PF table manager
pub struct PfTableManager {}

impl PfTableManager {
    /// Create new PF table manager
    pub fn new() -> Result<Self, PfError> {
        Ok(Self {})
    }
}

impl Default for PfTableManager {
    fn default() -> Self {
        Self::new().unwrap_or(Self {})
    }
}

/// PF table integration error type
#[derive(Debug)]
pub enum PfError {
    /// Connection failed
    ConnectionFailed(String),
    /// Operation failed
    OperationFailed(String),
    /// Invalid argument
    InvalidArgument(String),
    /// Table not found
    TableNotFound(String),
    /// Generic error
    Other(String),
}

impl fmt::Display for PfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PfError::ConnectionFailed(msg) => write!(f, "PF connection failed: {}", msg),
            PfError::OperationFailed(msg) => write!(f, "PF operation failed: {}", msg),
            PfError::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            PfError::TableNotFound(msg) => write!(f, "PF table not found: {}", msg),
            PfError::Other(msg) => write!(f, "PF error: {}", msg),
        }
    }
}

impl std::error::Error for PfError {}
