// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv6 State Machine
//!
//! Provides type-safe state transitions for DHCPv6 protocol (RFC 3315).

use super::protocol::Dhcpv6MessageType;

/// DHCPv6 client states (RFC 3315)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcpv6State {
    /// Initial state
    Init,
    
    /// Client has sent SOLICIT, waiting for ADVERTISE
    Soliciting,
    
    /// Client has received ADVERTISE, sent REQUEST, waiting for REPLY
    Requesting,
    
    /// Client has valid configuration (received REPLY)
    Bound,
    
    /// Client is renewing (sent RENEW, waiting for REPLY)
    Renewing,
    
    /// Client is rebinding (sent REBIND, waiting for REPLY)
    Rebinding,
    
    /// Configuration released
    Released,
}

/// DHCPv6 state machine
pub struct Dhcpv6StateMachine {
    /// Current state
    state: Dhcpv6State,
}

impl Dhcpv6StateMachine {
    /// Create new state machine in INIT state
    pub fn new() -> Self {
        Self {
            state: Dhcpv6State::Init,
        }
    }

    /// Get current state
    pub fn state(&self) -> Dhcpv6State {
        self.state
    }

    /// Process incoming message and transition state
    ///
    /// # Arguments
    ///
    /// * `msg_type` - Type of received DHCPv6 message
    ///
    /// # Returns
    ///
    /// Expected response message type, or None if no response needed
    pub fn process_message(&mut self, msg_type: Dhcpv6MessageType) -> Option<Dhcpv6MessageType> {
        use Dhcpv6MessageType::*;
        use Dhcpv6State::*;

        match (self.state, msg_type) {
            // From INIT: Client sends SOLICIT
            (Init, Solicit) => {
                self.state = Soliciting;
                Some(Advertise)
            }

            // From SOLICITING: Server responds with ADVERTISE
            (Soliciting, Advertise) => {
                // Client typically sends REQUEST in response
                Some(Request)
            }

            // From SOLICITING: Client sends REQUEST (with rapid commit)
            (Soliciting, Request) => {
                self.state = Requesting;
                Some(Reply)
            }

            // From REQUESTING: Server responds with REPLY
            (Requesting, Reply) => {
                self.state = Bound;
                None
            }

            // From BOUND: Client initiates RENEW
            (Bound, Renew) => {
                self.state = Renewing;
                Some(Reply)
            }

            // From RENEWING: Server responds with REPLY
            (Renewing, Reply) => {
                self.state = Bound;
                None
            }

            // From RENEWING: Timeout -> rebinding
            (Renewing, Rebind) => {
                self.state = Rebinding;
                Some(Reply)
            }

            // From REBINDING: Any server can respond with REPLY
            (Rebinding, Reply) => {
                self.state = Bound;
                None
            }

            // RELEASE from any state with configuration
            (Bound | Renewing | Rebinding, Release) => {
                self.state = Released;
                None
            }

            // INFORMATION-REQUEST (stateless)
            (_, InformationRequest) => {
                Some(Reply)
            }

            // CONFIRM (client checking address validity)
            (_, Confirm) => {
                Some(Reply)
            }

            // Invalid transitions
            _ => None,
        }
    }

    /// Reset to INIT state
    pub fn reset(&mut self) {
        self.state = Dhcpv6State::Init;
    }

    /// Check if in bound state (has valid configuration)
    pub fn is_bound(&self) -> bool {
        self.state == Dhcpv6State::Bound
    }
}

impl Default for Dhcpv6StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let sm = Dhcpv6StateMachine::new();
        assert_eq!(sm.state(), Dhcpv6State::Init);
    }

    #[test]
    fn test_solicit_advertise_sequence() {
        let mut sm = Dhcpv6StateMachine::new();
        
        // Client sends SOLICIT
        let response = sm.process_message(Dhcpv6MessageType::Solicit);
        assert_eq!(response, Some(Dhcpv6MessageType::Advertise));
        assert_eq!(sm.state(), Dhcpv6State::Soliciting);
        
        // Server sends ADVERTISE
        let response = sm.process_message(Dhcpv6MessageType::Advertise);
        assert_eq!(response, Some(Dhcpv6MessageType::Request));
        
        // Client sends REQUEST
        let response = sm.process_message(Dhcpv6MessageType::Request);
        assert_eq!(response, Some(Dhcpv6MessageType::Reply));
        assert_eq!(sm.state(), Dhcpv6State::Requesting);
        
        // Server sends REPLY
        let response = sm.process_message(Dhcpv6MessageType::Reply);
        assert_eq!(response, None);
        assert_eq!(sm.state(), Dhcpv6State::Bound);
        assert!(sm.is_bound());
    }

    #[test]
    fn test_release() {
        let mut sm = Dhcpv6StateMachine::new();
        
        // Get to BOUND state
        sm.process_message(Dhcpv6MessageType::Solicit);
        sm.process_message(Dhcpv6MessageType::Request);
        sm.process_message(Dhcpv6MessageType::Reply);
        assert_eq!(sm.state(), Dhcpv6State::Bound);
        
        // Release configuration
        sm.process_message(Dhcpv6MessageType::Release);
        assert_eq!(sm.state(), Dhcpv6State::Released);
    }

    #[test]
    fn test_information_request() {
        let mut sm = Dhcpv6StateMachine::new();
        
        // Information request can happen from any state
        let response = sm.process_message(Dhcpv6MessageType::InformationRequest);
        assert_eq!(response, Some(Dhcpv6MessageType::Reply));
    }
}
