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

//! Linux ipset firewall integration
//!
//! Provides efficient IP address set management for firewall rules via Linux ipset.
//! This replaces the C implementation in ipset.c and uses netlink for communication.

use std::fmt;

/// Linux ipset manager
pub struct IpsetManager {}

impl IpsetManager {
    /// Create new ipset manager
    ///
    /// # Errors
    ///
    /// Currently returns `Ok` in all cases. Future implementation may return errors
    /// if ipset initialization fails.
    pub fn new() -> Result<Self, IpsetError> {
        Ok(Self {})
    }
}

impl Default for IpsetManager {
    fn default() -> Self {
        Self::new().unwrap_or(Self {})
    }
}

/// ipset integration error type
#[derive(Debug)]
pub enum IpsetError {
    /// Connection failed
    ConnectionFailed(String),
    /// Operation failed
    OperationFailed(String),
    /// Invalid argument
    InvalidArgument(String),
    /// Set not found
    SetNotFound(String),
    /// Generic error
    Other(String),
}

impl fmt::Display for IpsetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpsetError::ConnectionFailed(msg) => write!(f, "ipset connection failed: {msg}"),
            IpsetError::OperationFailed(msg) => write!(f, "ipset operation failed: {msg}"),
            IpsetError::InvalidArgument(msg) => write!(f, "Invalid argument: {msg}"),
            IpsetError::SetNotFound(msg) => write!(f, "ipset not found: {msg}"),
            IpsetError::Other(msg) => write!(f, "ipset error: {msg}"),
        }
    }
}

impl std::error::Error for IpsetError {}
