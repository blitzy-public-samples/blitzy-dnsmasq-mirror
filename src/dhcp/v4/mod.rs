// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv4 Server Implementation
//!
//! This module provides the DHCPv4 server implementation, replacing C files:
//! - `src/dhcp.c` - DHCPv4 server logic
//! - `src/rfc2131.c` - RFC 2131 protocol implementation
//!
//! ## RFC 2131 Compliance
//!
//! Implements Dynamic Host Configuration Protocol (RFC 2131) with full state machine:
//! - DISCOVER → OFFER
//! - REQUEST → ACK/NAK
//! - RELEASE
//! - INFORM
//!
//! ## Architecture
//!
//! The DHCPv4 implementation is organized into:
//! - **server.rs** - Main server logic and message handling
//! - **protocol.rs** - RFC 2131 packet parsing and serialization
//! - **state_machine.rs** - Type-safe state transitions
//! - **options.rs** - DHCPv4 option parsing

pub mod options;
pub mod protocol;
pub mod server;
pub mod state_machine;

// Re-export key types for external use
pub use options::Dhcpv4Option;
pub use protocol::{Dhcpv4Message, Dhcpv4MessageType};
pub use server::Dhcpv4Server;
pub use state_machine::{Dhcpv4State, Dhcpv4StateMachine};
