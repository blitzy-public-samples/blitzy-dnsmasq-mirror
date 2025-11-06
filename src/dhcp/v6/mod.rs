// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv6 Server Implementation
//!
//! This module provides the DHCPv6 server implementation, replacing C files:
//! - `src/dhcp6.c` - DHCPv6 server logic
//! - `src/rfc3315.c` - RFC 3315 protocol implementation
//!
//! ## RFC 3315 Compliance
//!
//! Implements Dynamic Host Configuration Protocol for IPv6 (RFC 3315) with full state machine:
//! - SOLICIT → ADVERTISE
//! - REQUEST → REPLY
//! - RENEW → REPLY
//! - REBIND → REPLY
//! - RELEASE
//! - INFORMATION-REQUEST → REPLY
//!
//! ## Architecture
//!
//! The DHCPv6 implementation is organized into:
//! - **server.rs** - Main server logic and message handling
//! - **protocol.rs** - RFC 3315 packet parsing and serialization
//! - **state_machine.rs** - Type-safe state transitions
//! - **options.rs** - DHCPv6 option parsing (TLV format)

pub mod server;
pub mod protocol;
pub mod state_machine;
pub mod options;

// Re-export key types for external use
pub use server::Dhcpv6Server;
pub use protocol::{Dhcpv6Message, Dhcpv6MessageType};
pub use state_machine::{Dhcpv6State, Dhcpv6StateMachine};
pub use options::Dhcpv6Option;
