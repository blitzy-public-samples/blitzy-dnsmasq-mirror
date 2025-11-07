// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv6 Server
//!
//! Main DHCPv6 server implementation, replacing `src/dhcp6.c`.

use super::protocol::{Dhcpv6Message, Dhcpv6MessageType};
use super::state_machine::Dhcpv6StateMachine;
use crate::dhcp::lease::{Lease, LeaseType, LeaseV6};
use std::net::Ipv6Addr;

/// DHCPv6 server configuration
#[derive(Debug, Clone)]
pub struct Dhcpv6ServerConfig {
    /// Server DUID (DHCP Unique Identifier)
    pub server_duid: Vec<u8>,

    /// Network prefix for address assignment
    pub prefix: Ipv6Addr,

    /// Prefix length (typically 64)
    pub prefix_len: u8,

    /// DNS servers
    pub dns_servers: Vec<Ipv6Addr>,

    /// Domain search list
    pub domain_list: Vec<String>,

    /// Preferred lifetime (seconds)
    pub preferred_lifetime: u32,

    /// Valid lifetime (seconds)
    pub valid_lifetime: u32,

    /// Support rapid commit
    pub rapid_commit: bool,
}

/// DHCPv6 server
pub struct Dhcpv6Server {
    /// Server configuration
    config: Dhcpv6ServerConfig,

    /// State machine
    state_machine: Dhcpv6StateMachine,

    /// Active leases
    leases: Vec<Lease>,
}

impl Dhcpv6Server {
    /// Create new DHCPv6 server
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    pub fn new(config: Dhcpv6ServerConfig) -> Self {
        Self {
            config,
            state_machine: Dhcpv6StateMachine::new(0), // Initial transaction ID (unused in server-wide state machine)
            leases: Vec::new(),
        }
    }

    /// Handle incoming DHCPv6 message
    ///
    /// # Arguments
    ///
    /// * `message` - Received DHCPv6 message
    ///
    /// # Returns
    ///
    /// Response message if applicable
    pub fn handle_message(&mut self, message: Dhcpv6Message) -> Option<Dhcpv6Message> {
        let msg_type = self.message_type_from_u8(message.msg_type)?;

        match msg_type {
            Dhcpv6MessageType::Solicit => self.handle_solicit(message),
            Dhcpv6MessageType::Request => self.handle_request(message),
            Dhcpv6MessageType::Renew => self.handle_renew(message),
            Dhcpv6MessageType::Rebind => self.handle_rebind(message),
            Dhcpv6MessageType::Release => self.handle_release(message),
            Dhcpv6MessageType::InformationRequest => self.handle_information_request(message),
            Dhcpv6MessageType::Confirm => self.handle_confirm(message),
            _ => None,
        }
    }

    /// Handle SOLICIT message
    fn handle_solicit(&mut self, message: Dhcpv6Message) -> Option<Dhcpv6Message> {
        // TODO: Implement full SOLICIT logic
        // For now, return a basic ADVERTISE
        let mut response = Dhcpv6Message::new(2); // ADVERTISE
        response.transaction_id = message.transaction_id;
        Some(response)
    }

    /// Handle REQUEST message
    fn handle_request(&mut self, message: Dhcpv6Message) -> Option<Dhcpv6Message> {
        // TODO: Implement full REQUEST logic
        let mut response = Dhcpv6Message::new(7); // REPLY
        response.transaction_id = message.transaction_id;
        Some(response)
    }

    /// Handle RENEW message
    fn handle_renew(&mut self, message: Dhcpv6Message) -> Option<Dhcpv6Message> {
        // TODO: Implement RENEW logic
        let mut response = Dhcpv6Message::new(7); // REPLY
        response.transaction_id = message.transaction_id;
        Some(response)
    }

    /// Handle REBIND message
    fn handle_rebind(&mut self, message: Dhcpv6Message) -> Option<Dhcpv6Message> {
        // TODO: Implement REBIND logic
        let mut response = Dhcpv6Message::new(7); // REPLY
        response.transaction_id = message.transaction_id;
        Some(response)
    }

    /// Handle RELEASE message
    fn handle_release(&mut self, _message: Dhcpv6Message) -> Option<Dhcpv6Message> {
        // TODO: Remove lease from database
        None // No response to RELEASE
    }

    /// Handle INFORMATION-REQUEST message
    fn handle_information_request(&mut self, message: Dhcpv6Message) -> Option<Dhcpv6Message> {
        // TODO: Implement stateless configuration response
        let mut response = Dhcpv6Message::new(7); // REPLY
        response.transaction_id = message.transaction_id;
        Some(response)
    }

    /// Handle CONFIRM message
    fn handle_confirm(&mut self, message: Dhcpv6Message) -> Option<Dhcpv6Message> {
        // TODO: Validate client's addresses
        let mut response = Dhcpv6Message::new(7); // REPLY
        response.transaction_id = message.transaction_id;
        Some(response)
    }

    /// Convert u8 to message type
    fn message_type_from_u8(&self, value: u8) -> Option<Dhcpv6MessageType> {
        match value {
            1 => Some(Dhcpv6MessageType::Solicit),
            2 => Some(Dhcpv6MessageType::Advertise),
            3 => Some(Dhcpv6MessageType::Request),
            4 => Some(Dhcpv6MessageType::Confirm),
            5 => Some(Dhcpv6MessageType::Renew),
            6 => Some(Dhcpv6MessageType::Rebind),
            7 => Some(Dhcpv6MessageType::Reply),
            8 => Some(Dhcpv6MessageType::Release),
            9 => Some(Dhcpv6MessageType::Decline),
            10 => Some(Dhcpv6MessageType::Reconfigure),
            11 => Some(Dhcpv6MessageType::InformationRequest),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_server() {
        let config = Dhcpv6ServerConfig {
            server_duid: vec![0x00, 0x01, 0x00, 0x01],
            prefix: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
            prefix_len: 64,
            dns_servers: vec![Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)],
            domain_list: vec!["example.com".to_string()],
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
            rapid_commit: true,
        };

        let server = Dhcpv6Server::new(config);
        assert_eq!(server.leases.len(), 0);
    }
}
