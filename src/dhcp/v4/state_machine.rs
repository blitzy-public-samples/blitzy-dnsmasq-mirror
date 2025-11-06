// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv4 State Machine
//!
//! Provides type-safe state transitions for DHCPv4 protocol (RFC 2131).
//!
//! Replaces state management in C implementation (`src/dhcp.c`).

use super::protocol::{Dhcpv4MessageType, MessageType};

/// DHCPv4 client states (RFC 2131 Section 4.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcpv4State {
    /// Initial state - no configuration
    Init,

    /// Client has sent DISCOVER, waiting for OFFER
    Selecting,

    /// Client has received OFFER, sent REQUEST, waiting for ACK
    Requesting,

    /// Client has valid lease (received ACK)
    Bound,

    /// T1 timer expired, trying to renew with same server
    Renewing,

    /// T2 timer expired, trying to rebind with any server
    Rebinding,

    /// Lease released by client
    Released,
}

/// DHCPv4 state machine
pub struct Dhcpv4StateMachine {
    /// Current state
    state: Dhcpv4State,
}

impl Dhcpv4StateMachine {
    /// Create new state machine in INIT state
    pub fn new() -> Self {
        Self {
            state: Dhcpv4State::Init,
        }
    }

    /// Get current state
    pub fn state(&self) -> Dhcpv4State {
        self.state
    }

    /// Process incoming message and transition state
    ///
    /// # Arguments
    ///
    /// * `msg_type` - Type of received DHCPv4 message
    ///
    /// # Returns
    ///
    /// Expected response message type, or None if no response needed
    pub fn process_message(&mut self, msg_type: Dhcpv4MessageType) -> Option<Dhcpv4MessageType> {
        use MessageType::*;
        use Dhcpv4State::*;

        match (self.state, msg_type) {
            // From INIT: Client sends DISCOVER
            (Init, Discover) => {
                self.state = Selecting;
                Some(Offer)
            }

            // From SELECTING: Server responds to DISCOVER with OFFER
            (Selecting, Offer) => {
                // Client typically sends REQUEST in response
                Some(Request)
            }

            // From SELECTING: Client sends REQUEST (selected server)
            (Selecting, Request) => {
                self.state = Requesting;
                Some(Ack)
            }

            // From REQUESTING: Server responds with ACK
            (Requesting, Ack) => {
                self.state = Bound;
                None
            }

            // From REQUESTING: Server responds with NAK
            (Requesting, Nak) => {
                self.state = Init;
                None
            }

            // From BOUND: Lease expires or client renews
            (Bound, Request) => {
                self.state = Renewing;
                Some(Ack)
            }

            // From RENEWING: ACK received
            (Renewing, Ack) => {
                self.state = Bound;
                None
            }

            // From RENEWING: NAK or timeout -> rebinding
            (Renewing, Nak) => {
                self.state = Rebinding;
                None
            }

            // From REBINDING: Any server can ACK
            (Rebinding, Ack) => {
                self.state = Bound;
                None
            }

            // From REBINDING: NAK -> restart
            (Rebinding, Nak) => {
                self.state = Init;
                None
            }

            // RELEASE from any state with lease
            (Bound | Renewing | Rebinding, Release) => {
                self.state = Released;
                None
            }

            // INFORM message (client has IP, wants configuration)
            (_, Inform) => Some(Ack),

            // Invalid transitions
            _ => None,
        }
    }

    /// Reset to INIT state
    pub fn reset(&mut self) {
        self.state = Dhcpv4State::Init;
    }

    /// Check if in bound state (has valid lease)
    pub fn is_bound(&self) -> bool {
        self.state == Dhcpv4State::Bound
    }
}

impl Default for Dhcpv4StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let sm = Dhcpv4StateMachine::new();
        assert_eq!(sm.state(), Dhcpv4State::Init);
    }

    #[test]
    fn test_discover_offer_sequence() {
        let mut sm = Dhcpv4StateMachine::new();

        // Client sends DISCOVER
        let response = sm.process_message(Dhcpv4MessageType::Discover);
        assert_eq!(response, Some(Dhcpv4MessageType::Offer));
        assert_eq!(sm.state(), Dhcpv4State::Selecting);

        // Server sends OFFER
        let response = sm.process_message(Dhcpv4MessageType::Offer);
        assert_eq!(response, Some(Dhcpv4MessageType::Request));

        // Client sends REQUEST
        let response = sm.process_message(Dhcpv4MessageType::Request);
        assert_eq!(response, Some(Dhcpv4MessageType::Ack));
        assert_eq!(sm.state(), Dhcpv4State::Requesting);

        // Server sends ACK
        let response = sm.process_message(Dhcpv4MessageType::Ack);
        assert_eq!(response, None);
        assert_eq!(sm.state(), Dhcpv4State::Bound);
        assert!(sm.is_bound());
    }

    #[test]
    fn test_nak_returns_to_init() {
        let mut sm = Dhcpv4StateMachine::new();

        sm.process_message(Dhcpv4MessageType::Discover);
        sm.process_message(Dhcpv4MessageType::Request);

        // NAK should return to INIT
        sm.process_message(Dhcpv4MessageType::Nak);
        assert_eq!(sm.state(), Dhcpv4State::Init);
    }

    #[test]
    fn test_release() {
        let mut sm = Dhcpv4StateMachine::new();

        // Get to BOUND state
        sm.process_message(Dhcpv4MessageType::Discover);
        sm.process_message(Dhcpv4MessageType::Request);
        sm.process_message(Dhcpv4MessageType::Ack);
        assert_eq!(sm.state(), Dhcpv4State::Bound);

        // Release lease
        sm.process_message(Dhcpv4MessageType::Release);
        assert_eq!(sm.state(), Dhcpv4State::Released);
    }

    #[test]
    fn test_reset() {
        let mut sm = Dhcpv4StateMachine::new();
        sm.process_message(Dhcpv4MessageType::Discover);

        sm.reset();
        assert_eq!(sm.state(), Dhcpv4State::Init);
    }
}
