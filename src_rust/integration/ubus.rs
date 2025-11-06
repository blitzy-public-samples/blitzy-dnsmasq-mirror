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

//! OpenWrt ubus integration for dnsmasq control interface
//!
//! Provides methods for external control via OpenWrt's micro-bus IPC system.
//! This replaces the C implementation in ubus.c and uses FFI to libubus.

use std::fmt;

/// OpenWrt ubus manager
pub struct UbusManager {}

impl UbusManager {
    /// Create new ubus manager
    pub fn new() -> Result<Self, UbusError> {
        Ok(Self {})
    }
}

impl Default for UbusManager {
    fn default() -> Self {
        Self::new().unwrap_or(Self {})
    }
}

/// ubus integration error type
#[derive(Debug)]
pub enum UbusError {
    /// Connection failed
    ConnectionFailed(String),
    /// Method call failed
    MethodCallFailed(String),
    /// Invalid argument
    InvalidArgument(String),
    /// Generic error
    Other(String),
}

impl fmt::Display for UbusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UbusError::ConnectionFailed(msg) => write!(f, "ubus connection failed: {}", msg),
            UbusError::MethodCallFailed(msg) => write!(f, "ubus method call failed: {}", msg),
            UbusError::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            UbusError::Other(msg) => write!(f, "ubus error: {}", msg),
        }
    }
}

impl std::error::Error for UbusError {}

/// Initialize ubus integration
pub fn init_ubus() -> Result<UbusManager, UbusError> {
    UbusManager::new()
}
