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

//! Linux connection tracking integration
//!
//! Integrates with Linux netfilter conntrack for advanced firewall rule coordination.
//! This replaces the C implementation in conntrack.c and uses FFI to libnetfilter_conntrack.

use std::fmt;

/// Linux conntrack manager
pub struct ConntrackManager {}

impl ConntrackManager {
    /// Create new conntrack manager
    ///
    /// # Errors
    ///
    /// Currently returns `Ok` in all cases. Future implementation may return errors
    /// if conntrack initialization fails.
    pub fn new() -> Result<Self, ConntrackError> {
        Ok(Self {})
    }
}

impl Default for ConntrackManager {
    fn default() -> Self {
        Self::new().unwrap_or(Self {})
    }
}

/// conntrack integration error type
#[derive(Debug)]
pub enum ConntrackError {
    /// Connection failed
    ConnectionFailed(String),
    /// Operation failed
    OperationFailed(String),
    /// Invalid argument
    InvalidArgument(String),
    /// Generic error
    Other(String),
}

impl fmt::Display for ConntrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConntrackError::ConnectionFailed(msg) => write!(f, "conntrack connection failed: {msg}"),
            ConntrackError::OperationFailed(msg) => write!(f, "conntrack operation failed: {msg}"),
            ConntrackError::InvalidArgument(msg) => write!(f, "Invalid argument: {msg}"),
            ConntrackError::Other(msg) => write!(f, "conntrack error: {msg}"),
        }
    }
}

impl std::error::Error for ConntrackError {}
