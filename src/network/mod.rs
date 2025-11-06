// Copyright (c) 2000-2024 Simon Kelley & dnsmasq contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Network layer module
//!
//! This module provides network interface management, socket operations,
//! and packet I/O functionality for the dnsmasq-rs daemon.

pub mod interface;

// Re-export commonly used types for convenience
pub use interface::{
    enumerate_interfaces, index_to_name, name_to_index, watch_interfaces, InterfaceError,
    InterfaceEvent, InterfaceFlags, InterfaceRecord, is_interface_allowed,
};
