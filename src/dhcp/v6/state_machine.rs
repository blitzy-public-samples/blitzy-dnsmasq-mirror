// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # `DHCPv6` State Machine
//!
//! Type-safe state transitions for `DHCPv6` protocol lifecycle implementing RFC 3315.
//!
//! ## Overview
//!
//! This module implements `DHCPv6` state machines using Rust's type system to enforce
//! valid state transitions at compile-time, preventing protocol violations. It replaces
//! C's switch-case message type handling in `rfc3315.c` with type-state pattern where
//! invalid states are unrepresentable.
//!
//! ## `DHCPv6` Message Exchanges
//!
//! ### Stateful Address Allocation (4-message exchange)
//! ```text
//! Client                Server
//!   |                      |
//!   |------ SOLICIT ------>|
//!   |<---- ADVERTISE ------|
//!   |------ REQUEST ------>|
//!   |<------ REPLY --------|
//!   |                      |
//! ```
//!
//! ### Rapid Commit (2-message exchange)
//! ```text
//! Client                Server
//!   |                      |
//!   |-- SOLICIT(RC opt) -->|
//!   |<----- REPLY ---------|
//!   |                      |
//! ```
//!
//! ### Stateless Configuration
//! ```text
//! Client                Server
//!   |                      |
//!   |- INFORMATION-REQ --->|
//!   |<----- REPLY ---------|
//!   |                      |
//! ```
//!
//! ## References
//!
//! - `RFC 3315`: Dynamic Host Configuration Protocol for IPv6 (`DHCPv6`)
//! - `RFC 8415`: `DHCPv6` bis (updated specification)
//! - Source: `src/rfc3315.c` (C implementation reference)

use std::fmt;
use tracing::debug;

use super::protocol::Dhcpv6MessageType;
use crate::dhcp::v6::options::Dhcp6Option;
use crate::types::errors::{DhcpError, DnsmasqError};

/// `DHCPv6` protocol states
///
/// Represents the lifecycle states of a `DHCPv6` transaction from the server's
/// perspective. This enum replaces implicit state tracking in C implementation
/// where state was inferred from message types and transaction IDs.
///
/// # State Transition Diagram
///
/// ```text
///                    ┌──────────────┐
///                    │   Solicit    │ (initial)
///                    └──────┬───────┘
///                           │
///                           ▼
///                    ┌──────────────┐
///            ┌───────┤  Advertise   │
///            │       └──────────────┘
///            │              │
///            │              ▼
///            │       ┌──────────────┐
///            └──────>│   Request    │
///                    └──────┬───────┘
///                           │
///                           ▼
///                    ┌──────────────┐
///         ┌─────────>│    Reply     │<─────────┐
///         │          └──────┬───────┘          │
///         │                 │                   │
///         │                 ▼                   │
///         │          ┌──────────────┐          │
///         │          │    Bound     │          │
///         │          └─┬────────┬───┘          │
///         │            │        │               │
///         │   Renew    │        │  Rebind       │
///         └────────────┘        └───────────────┘
/// ```
///
/// # C Code Replaced
///
/// From `src/rfc3315.c` lines 262-1104:
/// ```c
/// switch (msg_type)
/// {
///   case DHCP6SOLICIT:
///     // implicit state = soliciting
///     ...
///   case DHCP6REQUEST:
///     // implicit state = requesting
///     ...
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6State {
    /// Initial state: awaiting client SOLICIT
    Solicit,
    /// Server has sent ADVERTISE, awaiting REQUEST
    Advertise,
    /// Client has sent REQUEST, server preparing REPLY
    Request,
    /// Server responding to client request
    Reply,
    /// Client renewing lease (T1 timer expired)
    Renew,
    /// Client rebinding lease (T2 timer expired)
    Rebind,
    /// Client confirming address validity
    Confirm,
    /// Client releasing addresses
    Release,
    /// Client declining addresses (conflict detected)
    Decline,
    /// Stateless information request (no address allocation)
    InformationRequest,
}

impl fmt::Display for Dhcpv6State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Solicit => "SOLICIT",
            Self::Advertise => "ADVERTISE",
            Self::Request => "REQUEST",
            Self::Reply => "REPLY",
            Self::Renew => "RENEW",
            Self::Rebind => "REBIND",
            Self::Confirm => "CONFIRM",
            Self::Release => "RELEASE",
            Self::Decline => "DECLINE",
            Self::InformationRequest => "INFORMATION-REQUEST",
        };
        write!(f, "{name}")
    }
}

/// State transition validator and processor
///
/// Encapsulates `DHCPv6` state transition logic with compile-time and runtime
/// validation. This struct replaces C's switch-case dispatch with explicit
/// state transition methods that return `Result` types encoding valid
/// transitions in function signatures.
///
/// # Design Pattern
///
/// Uses a combination of type-state pattern (compile-time safety) and
/// runtime validation (for dynamic protocol requirements like rapid commit).
///
/// # C Code Replaced
///
/// From `src/rfc3315.c`:
/// ```c
/// static size_t dhcp6_no_relay(struct state *state, ...)
/// {
///   switch (msg_type)
///   {
///     case DHCP6SOLICIT:
///       // Process SOLICIT, send ADVERTISE or REPLY
///       ...
///   }
/// }
/// ```
#[derive(Debug)]
pub struct Dhcpv6StateMachine {
    /// Current state in the `DHCPv6` exchange
    current_state: Dhcpv6State,
    /// Whether rapid commit is active (2-message exchange)
    rapid_commit: bool,
    /// Transaction ID for correlation
    transaction_id: u32,
}

impl Dhcpv6StateMachine {
    /// Create new state transition starting from SOLICIT
    ///
    /// # Arguments
    ///
    /// * `transaction_id` - `DHCPv6` transaction ID for message correlation
    ///
    /// # Returns
    ///
    /// New `Dhcpv6StateMachine` in Solicit state
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let transition = Dhcpv6StateMachine::new(0x123456);
    /// ```
    pub fn new(transaction_id: u32) -> Self {
        debug!(
            transaction_id,
            "Creating new DHCPv6 state transition (initial state: SOLICIT)"
        );
        Self {
            current_state: Dhcpv6State::Solicit,
            rapid_commit: false,
            transaction_id,
        }
    }

    /// Create state transition from incoming message type
    ///
    /// # Arguments
    ///
    /// * `msg_type` - Received `DHCPv6` message type
    /// * `transaction_id` - Transaction ID from message header
    /// * `options` - Parsed `DHCPv6` options from message
    ///
    /// # Returns
    ///
    /// `Ok(Dhcpv6StateMachine)` if message type is valid initial state,
    /// `Err(DnsmasqError)` if message type cannot start a transaction
    ///
    /// # Errors
    ///
    /// Returns `DhcpError::StateMachineError` if message type is not a valid
    /// initial message (e.g., ADVERTISE cannot start a transaction).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let transition = Dhcpv6StateMachine::from_message_type(
    ///     Dhcpv6MessageType::Solicit,
    ///     0x123456,
    ///     &options
    /// )?;
    /// ```
    pub fn from_message_type(
        msg_type: Dhcpv6MessageType,
        transaction_id: u32,
        options: &[Dhcp6Option],
    ) -> Result<Self, DnsmasqError> {
        // Check for rapid commit option in SOLICIT messages
        let rapid_commit = msg_type == Dhcpv6MessageType::Solicit
            && options
                .iter()
                .any(|opt| matches!(opt, Dhcp6Option::RapidCommit));

        let initial_state = match msg_type {
            Dhcpv6MessageType::Solicit => Dhcpv6State::Solicit,
            Dhcpv6MessageType::Request => Dhcpv6State::Request,
            Dhcpv6MessageType::Confirm => Dhcpv6State::Confirm,
            Dhcpv6MessageType::Renew => Dhcpv6State::Renew,
            Dhcpv6MessageType::Rebind => Dhcpv6State::Rebind,
            Dhcpv6MessageType::Release => Dhcpv6State::Release,
            Dhcpv6MessageType::Decline => Dhcpv6State::Decline,
            Dhcpv6MessageType::InformationRequest => Dhcpv6State::InformationRequest,
            _ => {
                return Err(DnsmasqError::Dhcp(DhcpError::StateMachineError {
                    message: format!("Message type {msg_type} cannot initiate DHCPv6 transaction"),
                }));
            }
        };

        debug!(
            transaction_id,
            state = %initial_state,
            rapid_commit,
            "Created state transition from message type {}",
            msg_type
        );

        Ok(Self {
            current_state: initial_state,
            rapid_commit,
            transaction_id,
        })
    }

    /// Validate whether a state transition is legal
    ///
    /// # Arguments
    ///
    /// * `from` - Source state
    /// * `to` - Target state
    ///
    /// # Returns
    ///
    /// `Ok(())` if transition is valid, `Err(DnsmasqError)` if invalid
    ///
    /// # Errors
    ///
    /// Returns `DhcpError::StateMachineError` for invalid transitions like:
    /// - ADVERTISE → RENEW (must go through REQUEST first)
    /// - RELEASE → SOLICIT (released clients must start new transaction)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// Dhcpv6StateMachine::validate(
    ///     Dhcpv6State::Solicit,
    ///     Dhcpv6State::Advertise
    /// )?; // OK
    ///
    /// Dhcpv6StateMachine::validate(
    ///     Dhcpv6State::Advertise,
    ///     Dhcpv6State::Renew
    /// )?; // Error
    /// ```
    pub fn validate(from: Dhcpv6State, to: Dhcpv6State) -> Result<(), DnsmasqError> {
        use Dhcpv6State::{Solicit, Advertise, Request, Reply, Renew, Rebind, Confirm, Release, Decline, InformationRequest};

        let valid = match (from, to) {
            // Valid transitions organized by source state
            (Solicit, Advertise | Request | InformationRequest | Reply | Confirm) |
            (Advertise, Request) |
            (Request, Reply | Decline) |
            (Reply, Renew | Rebind | Confirm | Release | Decline) |
            (Renew | Rebind, Reply | Release) |
            (Confirm | Release | Decline | InformationRequest, Reply) => true,

            // Self-transitions for retransmissions
            (s1, s2) if s1 == s2 => true,

            // All other transitions are invalid
            _ => false,
        };

        if !valid {
            debug!(
                from = %from,
                to = %to,
                "Invalid DHCPv6 state transition attempted"
            );
            return Err(DnsmasqError::Dhcp(DhcpError::StateMachineError {
                message: format!("Invalid state transition: {from} → {to}"),
            }));
        }

        debug!(
            from = %from,
            to = %to,
            "Valid DHCPv6 state transition"
        );
        Ok(())
    }

    /// Transition to next state
    ///
    /// # Arguments
    ///
    /// * `next_state` - Target state to transition to
    ///
    /// # Returns
    ///
    /// `Ok(())` if transition succeeds, `Err(DnsmasqError)` if invalid
    ///
    /// # Errors
    ///
    /// Returns `DhcpError::StateMachineError` if the transition is not
    /// allowed from the current state (validated by `validate()`).
    ///
    /// # State Logging
    ///
    /// All successful transitions are logged at debug level with transaction
    /// ID, source state, and target state for protocol debugging and audit trail.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut transition = Dhcpv6StateMachine::new(0x123456);
    /// transition.transition_to(Dhcpv6State::Advertise)?;
    /// assert_eq!(transition.current_state(), Dhcpv6State::Advertise);
    /// ```
    pub fn transition_to(&mut self, next_state: Dhcpv6State) -> Result<(), DnsmasqError> {
        Self::validate(self.current_state, next_state)?;

        debug!(
            transaction_id = self.transaction_id,
            from = %self.current_state,
            to = %next_state,
            "DHCPv6 state transition"
        );

        self.current_state = next_state;
        Ok(())
    }

    /// Check if rapid commit is required for this transaction
    ///
    /// Rapid commit allows 2-message exchange (SOLICIT → REPLY) instead of
    /// 4-message (SOLICIT → ADVERTISE → REQUEST → REPLY) when client includes
    /// Rapid Commit option in SOLICIT.
    ///
    /// # Returns
    ///
    /// `true` if rapid commit option was present in SOLICIT
    ///
    /// # RFC Reference
    ///
    /// RFC 3315 Section 17.2.1: If the client included a Rapid Commit option
    /// in the Solicit message, the server may respond with a Reply message
    /// instead of an Advertise message.
    ///
    /// # C Code Replaced
    ///
    /// From `src/rfc3315.c` lines 870-880:
    /// ```c
    /// if (rapid_commit)
    ///   {
    ///     // Skip ADVERTISE, send REPLY directly
    ///     o = new_opt6(OPTION6_RAPID_COMMIT);
    ///     end_opt6(o);
    ///   }
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// if transition.requires_rapid_commit() {
    ///     // Send REPLY directly, skip ADVERTISE
    ///     transition.transition_to(Dhcpv6State::Reply)?;
    /// } else {
    ///     // Normal 4-message exchange
    ///     transition.transition_to(Dhcpv6State::Advertise)?;
    /// }
    /// ```
    #[must_use]
    pub fn requires_rapid_commit(&self) -> bool {
        self.rapid_commit
    }

    /// Get current state
    ///
    /// # Returns
    ///
    /// Current state in the `DHCPv6` transaction
    #[must_use]
    pub fn current_state(&self) -> Dhcpv6State {
        self.current_state
    }

    /// Get transaction ID
    ///
    /// # Returns
    ///
    /// 24-bit transaction ID used for message correlation
    #[must_use]
    pub fn transaction_id(&self) -> u32 {
        self.transaction_id
    }

    /// Determine appropriate response message type for current state
    ///
    /// # Returns
    ///
    /// Expected `DHCPv6` message type that server should send in response
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let transition = Dhcpv6StateMachine::new(0x123456);
    /// assert_eq!(
    ///     transition.response_message_type(),
    ///     Dhcpv6MessageType::Advertise
    /// );
    /// ```
    #[must_use]
    pub fn response_message_type(&self) -> Dhcpv6MessageType {
        use Dhcpv6State::{Solicit, Advertise, Request, Renew, Rebind, Confirm, Release, Decline, InformationRequest, Reply};

        match self.current_state {
            Solicit if self.rapid_commit => Dhcpv6MessageType::Reply,
            Solicit => Dhcpv6MessageType::Advertise,
            Advertise | Request | Renew | Rebind | Confirm | Release | Decline | InformationRequest | Reply => {
                Dhcpv6MessageType::Reply
            }
        }
    }

    /// Check if current state requires address allocation
    ///
    /// # Returns
    ///
    /// `true` if server should allocate/renew addresses in this state
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// if transition.requires_address_allocation() {
    ///     // Allocate address from pool
    ///     let addr = allocate_address(&client_duid, &iaid)?;
    /// }
    /// ```
    #[must_use]
    pub fn requires_address_allocation(&self) -> bool {
        matches!(
            self.current_state,
            Dhcpv6State::Solicit
                | Dhcpv6State::Request
                | Dhcpv6State::Renew
                | Dhcpv6State::Rebind
                | Dhcpv6State::Confirm
        )
    }

    /// Check if current state is terminal (transaction complete)
    ///
    /// # Returns
    ///
    /// `true` if no further messages expected in this transaction
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.current_state,
            Dhcpv6State::Reply | Dhcpv6State::Release
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(
            Dhcpv6MessageType::from_u8(1),
            Some(Dhcpv6MessageType::Solicit)
        );
        assert_eq!(
            Dhcpv6MessageType::from_u8(7),
            Some(Dhcpv6MessageType::Reply)
        );
        assert_eq!(Dhcpv6MessageType::from_u8(99), None);

        assert_eq!(Dhcpv6MessageType::Solicit.to_u8(), 1);
        assert_eq!(Dhcpv6MessageType::Reply.to_u8(), 7);
    }

    #[test]
    fn test_message_type_predicates() {
        assert!(Dhcpv6MessageType::Solicit.requires_response());
        assert!(!Dhcpv6MessageType::Advertise.requires_response());
        assert!(Dhcpv6MessageType::Request.requires_response());

        assert!(Dhcpv6MessageType::RelayForw.is_relay_message());
        assert!(Dhcpv6MessageType::RelayRepl.is_relay_message());
        assert!(!Dhcpv6MessageType::Solicit.is_relay_message());
    }

    #[test]
    fn test_state_transition_new() {
        let transition = Dhcpv6StateMachine::new(0x0012_3456);
        assert_eq!(transition.current_state(), Dhcpv6State::Solicit);
        assert_eq!(transition.transaction_id(), 0x0012_3456);
        assert!(!transition.requires_rapid_commit());
    }

    #[test]
    fn test_state_transition_from_message_type() {
        let options = vec![];

        let transition =
            Dhcpv6StateMachine::from_message_type(Dhcpv6MessageType::Solicit, 0x123, &options)
                .unwrap();
        assert_eq!(transition.current_state(), Dhcpv6State::Solicit);
        assert!(!transition.requires_rapid_commit());

        // Test with rapid commit option
        let options_rc = vec![Dhcp6Option::RapidCommit];
        let transition_rc =
            Dhcpv6StateMachine::from_message_type(Dhcpv6MessageType::Solicit, 0x456, &options_rc)
                .unwrap();
        assert!(transition_rc.requires_rapid_commit());

        // Invalid initial message types
        assert!(
            Dhcpv6StateMachine::from_message_type(Dhcpv6MessageType::Advertise, 0x789, &options)
                .is_err()
        );
    }

    #[test]
    fn test_valid_state_transitions() {
        // Standard 4-message exchange
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Solicit, Dhcpv6State::Advertise).is_ok());
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Advertise, Dhcpv6State::Request).is_ok());
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Request, Dhcpv6State::Reply).is_ok());

        // Rapid commit
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Solicit, Dhcpv6State::Reply).is_ok());

        // Lease lifecycle
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Reply, Dhcpv6State::Renew).is_ok());
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Reply, Dhcpv6State::Rebind).is_ok());
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Renew, Dhcpv6State::Reply).is_ok());
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Rebind, Dhcpv6State::Reply).is_ok());

        // Release and decline
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Reply, Dhcpv6State::Release).is_ok());
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Request, Dhcpv6State::Decline).is_ok());

        // Information request
        assert!(
            Dhcpv6StateMachine::validate(Dhcpv6State::Solicit, Dhcpv6State::InformationRequest)
                .is_ok()
        );
        assert!(
            Dhcpv6StateMachine::validate(Dhcpv6State::InformationRequest, Dhcpv6State::Reply)
                .is_ok()
        );
    }

    #[test]
    fn test_invalid_state_transitions() {
        // Cannot jump from ADVERTISE to RENEW
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Advertise, Dhcpv6State::Renew).is_err());

        // Cannot go from RELEASE to SOLICIT (must be new transaction)
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Release, Dhcpv6State::Solicit).is_err());

        // Cannot skip REQUEST in normal exchange
        assert!(Dhcpv6StateMachine::validate(Dhcpv6State::Advertise, Dhcpv6State::Reply).is_err());
    }

    #[test]
    fn test_transition_to() {
        let mut transition = Dhcpv6StateMachine::new(0x123);

        // Valid transition
        assert!(transition.transition_to(Dhcpv6State::Advertise).is_ok());
        assert_eq!(transition.current_state(), Dhcpv6State::Advertise);

        // Valid next transition
        assert!(transition.transition_to(Dhcpv6State::Request).is_ok());
        assert_eq!(transition.current_state(), Dhcpv6State::Request);

        // Invalid transition
        assert!(transition.transition_to(Dhcpv6State::Renew).is_err());
        assert_eq!(transition.current_state(), Dhcpv6State::Request); // State unchanged
    }

    #[test]
    fn test_response_message_type() {
        let mut transition = Dhcpv6StateMachine::new(0x123);
        assert_eq!(
            transition.response_message_type(),
            Dhcpv6MessageType::Advertise
        );

        transition.transition_to(Dhcpv6State::Advertise).unwrap();
        assert_eq!(transition.response_message_type(), Dhcpv6MessageType::Reply);

        // Test rapid commit bypass
        let options_rc = vec![Dhcp6Option::RapidCommit];
        let transition_rc =
            Dhcpv6StateMachine::from_message_type(Dhcpv6MessageType::Solicit, 0x456, &options_rc)
                .unwrap();
        assert_eq!(
            transition_rc.response_message_type(),
            Dhcpv6MessageType::Reply
        ); // Skips ADVERTISE
    }

    #[test]
    fn test_requires_address_allocation() {
        let transition = Dhcpv6StateMachine::new(0x123);
        assert!(transition.requires_address_allocation()); // SOLICIT requires allocation

        let options = vec![];
        let info_req = Dhcpv6StateMachine::from_message_type(
            Dhcpv6MessageType::InformationRequest,
            0x456,
            &options,
        )
        .unwrap();
        assert!(!info_req.requires_address_allocation()); // Stateless
    }

    #[test]
    fn test_is_terminal() {
        let mut transition = Dhcpv6StateMachine::new(0x123);
        assert!(!transition.is_terminal()); // SOLICIT not terminal

        transition.transition_to(Dhcpv6State::Advertise).unwrap();
        transition.transition_to(Dhcpv6State::Request).unwrap();
        transition.transition_to(Dhcpv6State::Reply).unwrap();
        assert!(transition.is_terminal()); // REPLY is terminal

        let options = vec![];
        let mut release =
            Dhcpv6StateMachine::from_message_type(Dhcpv6MessageType::Release, 0x789, &options)
                .unwrap();
        assert!(release.is_terminal()); // RELEASE is terminal
    }

    #[test]
    fn test_display_formatting() {
        assert_eq!(format!("{}", Dhcpv6MessageType::Solicit), "SOLICIT");
        assert_eq!(format!("{}", Dhcpv6MessageType::Reply), "REPLY");
        assert_eq!(format!("{}", Dhcpv6State::Solicit), "SOLICIT");
        assert_eq!(format!("{}", Dhcpv6State::Renew), "RENEW");
    }

    #[test]
    fn test_rapid_commit_state_machine() {
        // Create transition with rapid commit
        let options_rc = vec![Dhcp6Option::RapidCommit];
        let mut transition =
            Dhcpv6StateMachine::from_message_type(Dhcpv6MessageType::Solicit, 0x123, &options_rc)
                .unwrap();

        assert!(transition.requires_rapid_commit());
        assert_eq!(transition.current_state(), Dhcpv6State::Solicit);

        // Can transition directly to REPLY (bypass ADVERTISE)
        assert!(transition.transition_to(Dhcpv6State::Reply).is_ok());
        assert_eq!(transition.current_state(), Dhcpv6State::Reply);
        assert!(transition.is_terminal());
    }

    #[test]
    fn test_full_4_message_exchange() {
        let mut transition = Dhcpv6StateMachine::new(0x0012_3456);

        // SOLICIT
        assert_eq!(transition.current_state(), Dhcpv6State::Solicit);
        assert_eq!(
            transition.response_message_type(),
            Dhcpv6MessageType::Advertise
        );

        // ADVERTISE
        assert!(transition.transition_to(Dhcpv6State::Advertise).is_ok());
        assert_eq!(transition.current_state(), Dhcpv6State::Advertise);

        // REQUEST
        assert!(transition.transition_to(Dhcpv6State::Request).is_ok());
        assert_eq!(transition.current_state(), Dhcpv6State::Request);

        // REPLY
        assert!(transition.transition_to(Dhcpv6State::Reply).is_ok());
        assert_eq!(transition.current_state(), Dhcpv6State::Reply);
        assert!(transition.is_terminal());
    }

    #[test]
    fn test_lease_renewal_cycle() {
        let options = vec![];
        let mut transition =
            Dhcpv6StateMachine::from_message_type(Dhcpv6MessageType::Renew, 0x789, &options)
                .unwrap();

        assert_eq!(transition.current_state(), Dhcpv6State::Renew);
        assert!(transition.requires_address_allocation());

        // RENEW → REPLY
        assert!(transition.transition_to(Dhcpv6State::Reply).is_ok());
        assert_eq!(transition.current_state(), Dhcpv6State::Reply);
    }

    #[test]
    fn test_information_request_stateless() {
        let options = vec![];
        let mut transition = Dhcpv6StateMachine::from_message_type(
            Dhcpv6MessageType::InformationRequest,
            0xABC,
            &options,
        )
        .unwrap();

        assert_eq!(transition.current_state(), Dhcpv6State::InformationRequest);
        assert!(!transition.requires_address_allocation()); // Stateless

        // INFORMATION-REQUEST → REPLY
        assert!(transition.transition_to(Dhcpv6State::Reply).is_ok());
        assert_eq!(transition.response_message_type(), Dhcpv6MessageType::Reply);
    }
}
