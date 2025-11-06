// Copyright (c) 2000-2024 Simon Kelley & dnsmasq contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Network layer module
//!
//! This module provides network interface management, socket operations,
//! packet I/O functionality, and ARP cache querying for the dnsmasq-rs daemon.

pub mod arp;
pub mod interface;
pub mod packet;

// Re-export commonly used types for convenience
pub use arp::{
    find_mac, AddressFamily, ArpCache, ArpError, ArpRecord, ArpStatus, MacAddr,
};

pub use interface::{
    enumerate_interfaces, index_to_name, name_to_index, watch_interfaces, InterfaceError,
    InterfaceEvent, InterfaceFlags, InterfaceRecord, is_interface_allowed,
};

pub use packet::{
    cursor_from_buffer, cursor_from_buffer_mut, EdnsConfig, PacketBuffer, PacketBufferPool,
    PacketError, PacketReader, PacketWriter, Protocol, DNS_PACKET_SIZE, EDNS_PKTSZ,
    MAX_DOMAIN_NAME,
};

#[cfg(feature = "dnssec")]
pub use packet::DnssecBuffers;
