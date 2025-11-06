// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv4 Server
//!
//! Main DHCPv4 server implementation, replacing `src/dhcp.c`.

use super::protocol::{Dhcpv4Message, Dhcpv4MessageType};
use super::state_machine::Dhcpv4StateMachine;
use crate::dhcp::lease::{Lease, LeaseFlags, LeaseV4};
use std::net::Ipv4Addr;

/// DHCPv4 server configuration
#[derive(Debug, Clone)]
pub struct Dhcpv4ServerConfig {
    /// Server IP address (DHCP server identifier)
    pub server_addr: Ipv4Addr,

    /// Network range start
    pub range_start: Ipv4Addr,

    /// Network range end
    pub range_end: Ipv4Addr,

    /// Subnet mask
    pub netmask: Ipv4Addr,

    /// Default gateway (router)
    pub gateway: Option<Ipv4Addr>,

    /// DNS servers
    pub dns_servers: Vec<Ipv4Addr>,

    /// Default lease time (seconds)
    pub default_lease_time: u32,

    /// Maximum lease time (seconds)
    pub max_lease_time: u32,
}

/// DHCPv4 server
pub struct Dhcpv4Server {
    /// Server configuration
    config: Dhcpv4ServerConfig,

    /// State machine
    state_machine: Dhcpv4StateMachine,

    /// Active leases
    leases: Vec<Lease>,
}

impl Dhcpv4Server {
    /// Create new DHCPv4 server
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    pub fn new(config: Dhcpv4ServerConfig) -> Self {
        Self {
            config,
            state_machine: Dhcpv4StateMachine::new(),
            leases: Vec::new(),
        }
    }

    /// Handle incoming DHCPv4 message
    ///
    /// # Arguments
    ///
    /// * `message` - Received DHCPv4 message
    ///
    /// # Returns
    ///
    /// Response message if applicable
    pub fn handle_message(&mut self, message: Dhcpv4Message) -> Option<Dhcpv4Message> {
        // Parse message type from options
        let msg_type = self.extract_message_type(&message)?;

        match msg_type {
            Dhcpv4MessageType::Discover => self.handle_discover(message),
            Dhcpv4MessageType::Request => self.handle_request(message),
            Dhcpv4MessageType::Release => self.handle_release(message),
            Dhcpv4MessageType::Inform => self.handle_inform(message),
            _ => None,
        }
    }

    /// Handle DISCOVER message
    fn handle_discover(&mut self, _message: Dhcpv4Message) -> Option<Dhcpv4Message> {
        // TODO: Implement full DISCOVER logic
        // For now, return a basic OFFER
        let mut response = Dhcpv4Message::new();
        response.op = 2; // BOOTREPLY
        Some(response)
    }

    /// Handle REQUEST message
    fn handle_request(&mut self, _message: Dhcpv4Message) -> Option<Dhcpv4Message> {
        // TODO: Implement full REQUEST logic
        let mut response = Dhcpv4Message::new();
        response.op = 2; // BOOTREPLY
        Some(response)
    }

    /// Handle RELEASE message
    fn handle_release(&mut self, message: Dhcpv4Message) -> Option<Dhcpv4Message> {
        // Find and remove lease
        let client_addr = message.ciaddr;
        self.leases.retain(|lease| {
            if let Lease::V4(l) = lease {
                l.addr != client_addr
            } else {
                true
            }
        });

        None // No response to RELEASE
    }

    /// Handle INFORM message
    fn handle_inform(&mut self, _message: Dhcpv4Message) -> Option<Dhcpv4Message> {
        // TODO: Implement INFORM response
        let mut response = Dhcpv4Message::new();
        response.op = 2; // BOOTREPLY
        Some(response)
    }

    /// Extract message type from options
    fn extract_message_type(&self, message: &Dhcpv4Message) -> Option<Dhcpv4MessageType> {
        // TODO: Parse options to extract message type
        // For now, return None
        let _ = message;
        None
    }

    /// Allocate IP address from pool
    fn allocate_address(&mut self, hwaddr: &[u8]) -> Option<Ipv4Addr> {
        // TODO: Implement address allocation logic
        // For now, return a placeholder
        let _ = hwaddr;
        Some(self.config.range_start)
    }

    /// Find existing lease for hardware address
    fn find_lease(&self, hwaddr: &[u8]) -> Option<&Lease> {
        self.leases.iter().find(|lease| {
            if let Lease::V4(l) = lease {
                l.hwaddr == hwaddr
            } else {
                false
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_server() {
        let config = Dhcpv4ServerConfig {
            server_addr: Ipv4Addr::new(192, 168, 1, 1),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 200),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            default_lease_time: 3600,
            max_lease_time: 7200,
        };

        let server = Dhcpv4Server::new(config);
        assert_eq!(server.leases.len(), 0);
    }
}
