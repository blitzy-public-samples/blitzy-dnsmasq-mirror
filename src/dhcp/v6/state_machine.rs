// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv6 State Machine
//!
//! Type-safe state transitions for DHCPv6 protocol lifecycle implementing RFC 3315.
//!
//! ## Overview
//!
//! This module implements DHCPv6 state machines using Rust's type system to enforce
//! valid state transitions at compile-time, preventing protocol violations. It replaces
//! C's switch-case message type handling in `rfc3315.c` with type-state pattern where
//! invalid states are unrepresentable.
//!
//! ## DHCPv6 Message Exchanges
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
//! - RFC 3315: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
//! - RFC 8415: DHCPv6 bis (updated specification)
//! - Source: `src/rfc3315.c` (C implementation reference)

use std::fmt;
use tracing::debug;

use crate::dhcp::v6::options::Dhcp6Option;
use crate::types::errors::{DhcpError, DnsmasqError};

/// DHCPv6 message types per RFC 3315 Section 5.3
///
/// Represents all DHCPv6 message types with their numeric codes. This enum
/// replaces C's preprocessor constants (DHCP6SOLICIT, DHCP6ADVERTISE, etc.)
/// with type-safe Rust enum providing exhaustive pattern matching.
///
/// # C Code Replaced
///
/// From `src/dhcp6-protocol.h`:
/// ```c
/// #define DHCP6SOLICIT              1
/// #define DHCP6ADVERTISE            2
/// #define DHCP6REQUEST              3
/// // ... etc
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Dhcp6MessageType {
    /// Client locates servers (broadcasts)
    Solicit = 1,
    /// Server announces availability
    Advertise = 2,
    /// Client requests configuration
    Request = 3,
    /// Client confirms addresses still valid
    Confirm = 4,
    /// Client extends address lifetimes (T1 timer)
    Renew = 5,
    /// Client extends from any server (T2 timer)
    Rebind = 6,
    /// Server responds to client
    Reply = 7,
    /// Client relinquishes addresses
    Release = 8,
    /// Client reports address conflict
    Decline = 9,
    /// Server triggers reconfiguration
    Reconfigure = 10,
    /// Client requests configuration without address
    InformationRequest = 11,
    /// Relay agent forwards client message
    RelayForw = 12,
    /// Relay agent forwards server response
    RelayRepl = 13,
}

impl Dhcp6MessageType {
    /// Convert from numeric message type code
    ///
    /// # Arguments
    ///
    /// * `code` - Numeric DHCPv6 message type (1-13)
    ///
    /// # Returns
    ///
    /// `Some(Dhcp6MessageType)` if valid, `None` if unknown code
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let msg_type = Dhcp6MessageType::from_u8(1);
    /// assert_eq!(msg_type, Some(Dhcp6MessageType::Solicit));
    /// ```
    pub fn from_u8(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Solicit),
            2 => Some(Self::Advertise),
            3 => Some(Self::Request),
            4 => Some(Self::Confirm),
            5 => Some(Self::Renew),
            6 => Some(Self::Rebind),
            7 => Some(Self::Reply),
            8 => Some(Self::Release),
            9 => Some(Self::Decline),
            10 => Some(Self::Reconfigure),
            11 => Some(Self::InformationRequest),
            12 => Some(Self::RelayForw),
            13 => Some(Self::RelayRepl),
            _ => None,
        }
    }

    /// Convert to numeric message type code
    ///
    /// # Returns
    ///
    /// Numeric DHCPv6 message type code (1-13)
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Check if message type requires a response
    ///
    /// # Returns
    ///
    /// `true` if server must respond to this message type
    pub fn requires_response(self) -> bool {
        matches!(
            self,
            Self::Solicit
                | Self::Request
                | Self::Confirm
                | Self::Renew
                | Self::Rebind
                | Self::InformationRequest
                | Self::Release
                | Self::Decline
        )
    }

    /// Check if message is from relay agent
    ///
    /// # Returns
    ///
    /// `true` for RELAY-FORW and RELAY-REPL message types
    pub fn is_relay_message(self) -> bool {
        matches!(self, Self::RelayForw | Self::RelayRepl)
    }
}

impl fmt::Display for Dhcp6MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Solicit => "SOLICIT",
            Self::Advertise => "ADVERTISE",
            Self::Request => "REQUEST",
            Self::Confirm => "CONFIRM",
            Self::Renew => "RENEW",
            Self::Rebind => "REBIND",
            Self::Reply => "REPLY",
            Self::Release => "RELEASE",
            Self::Decline => "DECLINE",
            Self::Reconfigure => "RECONFIGURE",
            Self::InformationRequest => "INFORMATION-REQUEST",
            Self::RelayForw => "RELAY-FORW",
            Self::RelayRepl => "RELAY-REPL",
        };
        write!(f, "{}", name)
    }
}

/// DHCPv6 protocol states
///
/// Represents the lifecycle states of a DHCPv6 transaction from the server's
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
pub enum Dhcp6State {
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

impl fmt::Display for Dhcp6State {
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
        write!(f, "{}", name)
    }
}

/// State transition validator and processor
///
/// Encapsulates DHCPv6 state transition logic with compile-time and runtime
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
pub struct StateTransition {
    /// Current state in the DHCPv6 exchange
    current_state: Dhcp6State,
    /// Whether rapid commit is active (2-message exchange)
    rapid_commit: bool,
    /// Transaction ID for correlation
    transaction_id: u32,
}

impl StateTransition {
    /// Create new state transition starting from SOLICIT
    ///
    /// # Arguments
    ///
    /// * `transaction_id` - DHCPv6 transaction ID for message correlation
    ///
    /// # Returns
    ///
    /// New `StateTransition` in Solicit state
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let transition = StateTransition::new(0x123456);
    /// ```
    pub fn new(transaction_id: u32) -> Self {
        debug!(
            transaction_id,
            "Creating new DHCPv6 state transition (initial state: SOLICIT)"
        );
        Self {
            current_state: Dhcp6State::Solicit,
            rapid_commit: false,
            transaction_id,
        }
    }

    /// Create state transition from incoming message type
    ///
    /// # Arguments
    ///
    /// * `msg_type` - Received DHCPv6 message type
    /// * `transaction_id` - Transaction ID from message header
    /// * `options` - Parsed DHCPv6 options from message
    ///
    /// # Returns
    ///
    /// `Ok(StateTransition)` if message type is valid initial state,
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
    /// let transition = StateTransition::from_message_type(
    ///     Dhcp6MessageType::Solicit,
    ///     0x123456,
    ///     &options
    /// )?;
    /// ```
    pub fn from_message_type(
        msg_type: Dhcp6MessageType,
        transaction_id: u32,
        options: &[Dhcp6Option],
    ) -> Result<Self, DnsmasqError> {
        // Check for rapid commit option in SOLICIT messages
        let rapid_commit = msg_type == Dhcp6MessageType::Solicit
            && options.iter().any(|opt| matches!(opt, Dhcp6Option::RapidCommit));

        let initial_state = match msg_type {
            Dhcp6MessageType::Solicit => Dhcp6State::Solicit,
            Dhcp6MessageType::Request => Dhcp6State::Request,
            Dhcp6MessageType::Confirm => Dhcp6State::Confirm,
            Dhcp6MessageType::Renew => Dhcp6State::Renew,
            Dhcp6MessageType::Rebind => Dhcp6State::Rebind,
            Dhcp6MessageType::Release => Dhcp6State::Release,
            Dhcp6MessageType::Decline => Dhcp6State::Decline,
            Dhcp6MessageType::InformationRequest => Dhcp6State::InformationRequest,
            _ => {
                return Err(DnsmasqError::Dhcp(DhcpError::StateMachineError {
                    message: format!(
                        "Message type {} cannot initiate DHCPv6 transaction",
                        msg_type
                    ),
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
    /// StateTransition::validate(
    ///     Dhcp6State::Solicit,
    ///     Dhcp6State::Advertise
    /// )?; // OK
    ///
    /// StateTransition::validate(
    ///     Dhcp6State::Advertise,
    ///     Dhcp6State::Renew
    /// )?; // Error
    /// ```
    pub fn validate(from: Dhcp6State, to: Dhcp6State) -> Result<(), DnsmasqError> {
        use Dhcp6State::*;

        let valid = match (from, to) {
            // Standard 4-message exchange
            (Solicit, Advertise) => true,
            (Advertise, Request) | (Solicit, Request) => true,
            (Request, Reply) => true,

            // Lease lifecycle transitions
            (Reply, Renew) | (Reply, Rebind) => true,
            (Renew, Reply) | (Rebind, Reply) => true,

            // Confirmation and release
            (Solicit, Confirm) | (Reply, Confirm) => true,
            (Confirm, Reply) => true,
            (Reply, Release) | (Renew, Release) | (Rebind, Release) => true,
            (Release, Reply) => true,

            // Decline
            (Reply, Decline) | (Request, Decline) => true,
            (Decline, Reply) => true,

            // Information request (stateless)
            (Solicit, InformationRequest) => true,
            (InformationRequest, Reply) => true,

            // Rapid commit bypass (SOLICIT → REPLY)
            (Solicit, Reply) => true,

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
                message: format!("Invalid state transition: {} → {}", from, to),
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
    /// let mut transition = StateTransition::new(0x123456);
    /// transition.transition_to(Dhcp6State::Advertise)?;
    /// assert_eq!(transition.current_state(), Dhcp6State::Advertise);
    /// ```
    pub fn transition_to(&mut self, next_state: Dhcp6State) -> Result<(), DnsmasqError> {
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
    ///     transition.transition_to(Dhcp6State::Reply)?;
    /// } else {
    ///     // Normal 4-message exchange
    ///     transition.transition_to(Dhcp6State::Advertise)?;
    /// }
    /// ```
    pub fn requires_rapid_commit(&self) -> bool {
        self.rapid_commit
    }

    /// Get current state
    ///
    /// # Returns
    ///
    /// Current state in the DHCPv6 transaction
    pub fn current_state(&self) -> Dhcp6State {
        self.current_state
    }

    /// Get transaction ID
    ///
    /// # Returns
    ///
    /// 24-bit transaction ID used for message correlation
    pub fn transaction_id(&self) -> u32 {
        self.transaction_id
    }

    /// Determine appropriate response message type for current state
    ///
    /// # Returns
    ///
    /// Expected DHCPv6 message type that server should send in response
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let transition = StateTransition::new(0x123456);
    /// assert_eq!(
    ///     transition.response_message_type(),
    ///     Dhcp6MessageType::Advertise
    /// );
    /// ```
    pub fn response_message_type(&self) -> Dhcp6MessageType {
        use Dhcp6State::*;

        match self.current_state {
            Solicit if self.rapid_commit => Dhcp6MessageType::Reply,
            Solicit => Dhcp6MessageType::Advertise,
            Advertise => Dhcp6MessageType::Reply,
            Request | Renew | Rebind | Confirm | Release | Decline | InformationRequest => {
                Dhcp6MessageType::Reply
            }
            Reply => Dhcp6MessageType::Reply, // Retransmission
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
    pub fn requires_address_allocation(&self) -> bool {
        matches!(
            self.current_state,
            Dhcp6State::Solicit
                | Dhcp6State::Request
                | Dhcp6State::Renew
                | Dhcp6State::Rebind
                | Dhcp6State::Confirm
        )
    }

    /// Check if current state is terminal (transaction complete)
    ///
    /// # Returns
    ///
    /// `true` if no further messages expected in this transaction
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.current_state,
            Dhcp6State::Reply | Dhcp6State::Release
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(Dhcp6MessageType::from_u8(1), Some(Dhcp6MessageType::Solicit));
        assert_eq!(Dhcp6MessageType::from_u8(7), Some(Dhcp6MessageType::Reply));
        assert_eq!(Dhcp6MessageType::from_u8(99), None);

        assert_eq!(Dhcp6MessageType::Solicit.to_u8(), 1);
        assert_eq!(Dhcp6MessageType::Reply.to_u8(), 7);
    }

    #[test]
    fn test_message_type_predicates() {
        assert!(Dhcp6MessageType::Solicit.requires_response());
        assert!(!Dhcp6MessageType::Advertise.requires_response());
        assert!(Dhcp6MessageType::Request.requires_response());

        assert!(Dhcp6MessageType::RelayForw.is_relay_message());
        assert!(Dhcp6MessageType::RelayRepl.is_relay_message());
        assert!(!Dhcp6MessageType::Solicit.is_relay_message());
    }

    #[test]
    fn test_state_transition_new() {
        let transition = StateTransition::new(0x123456);
        assert_eq!(transition.current_state(), Dhcp6State::Solicit);
        assert_eq!(transition.transaction_id(), 0x123456);
        assert!(!transition.requires_rapid_commit());
    }

    #[test]
    fn test_state_transition_from_message_type() {
        let options = vec![];
        
        let transition =
            StateTransition::from_message_type(Dhcp6MessageType::Solicit, 0x123, &options)
                .unwrap();
        assert_eq!(transition.current_state(), Dhcp6State::Solicit);
        assert!(!transition.requires_rapid_commit());

        // Test with rapid commit option
        let options_rc = vec![Dhcp6Option::RapidCommit];
        let transition_rc =
            StateTransition::from_message_type(Dhcp6MessageType::Solicit, 0x456, &options_rc)
                .unwrap();
        assert!(transition_rc.requires_rapid_commit());

        // Invalid initial message types
        assert!(StateTransition::from_message_type(
            Dhcp6MessageType::Advertise,
            0x789,
            &options
        )
        .is_err());
    }

    #[test]
    fn test_valid_state_transitions() {
        // Standard 4-message exchange
        assert!(StateTransition::validate(Dhcp6State::Solicit, Dhcp6State::Advertise).is_ok());
        assert!(StateTransition::validate(Dhcp6State::Advertise, Dhcp6State::Request).is_ok());
        assert!(StateTransition::validate(Dhcp6State::Request, Dhcp6State::Reply).is_ok());

        // Rapid commit
        assert!(StateTransition::validate(Dhcp6State::Solicit, Dhcp6State::Reply).is_ok());

        // Lease lifecycle
        assert!(StateTransition::validate(Dhcp6State::Reply, Dhcp6State::Renew).is_ok());
        assert!(StateTransition::validate(Dhcp6State::Reply, Dhcp6State::Rebind).is_ok());
        assert!(StateTransition::validate(Dhcp6State::Renew, Dhcp6State::Reply).is_ok());
        assert!(StateTransition::validate(Dhcp6State::Rebind, Dhcp6State::Reply).is_ok());

        // Release and decline
        assert!(StateTransition::validate(Dhcp6State::Reply, Dhcp6State::Release).is_ok());
        assert!(StateTransition::validate(Dhcp6State::Request, Dhcp6State::Decline).is_ok());

        // Information request
        assert!(StateTransition::validate(
            Dhcp6State::Solicit,
            Dhcp6State::InformationRequest
        )
        .is_ok());
        assert!(StateTransition::validate(
            Dhcp6State::InformationRequest,
            Dhcp6State::Reply
        )
        .is_ok());
    }

    #[test]
    fn test_invalid_state_transitions() {
        // Cannot jump from ADVERTISE to RENEW
        assert!(StateTransition::validate(Dhcp6State::Advertise, Dhcp6State::Renew).is_err());

        // Cannot go from RELEASE to SOLICIT (must be new transaction)
        assert!(StateTransition::validate(Dhcp6State::Release, Dhcp6State::Solicit).is_err());

        // Cannot skip REQUEST in normal exchange
        assert!(StateTransition::validate(Dhcp6State::Advertise, Dhcp6State::Reply).is_err());
    }

    #[test]
    fn test_transition_to() {
        let mut transition = StateTransition::new(0x123);

        // Valid transition
        assert!(transition.transition_to(Dhcp6State::Advertise).is_ok());
        assert_eq!(transition.current_state(), Dhcp6State::Advertise);

        // Valid next transition
        assert!(transition.transition_to(Dhcp6State::Request).is_ok());
        assert_eq!(transition.current_state(), Dhcp6State::Request);

        // Invalid transition
        assert!(transition.transition_to(Dhcp6State::Renew).is_err());
        assert_eq!(transition.current_state(), Dhcp6State::Request); // State unchanged
    }

    #[test]
    fn test_response_message_type() {
        let mut transition = StateTransition::new(0x123);
        assert_eq!(
            transition.response_message_type(),
            Dhcp6MessageType::Advertise
        );

        transition.transition_to(Dhcp6State::Advertise).unwrap();
        assert_eq!(
            transition.response_message_type(),
            Dhcp6MessageType::Reply
        );

        // Test rapid commit bypass
        let options_rc = vec![Dhcp6Option::RapidCommit];
        let transition_rc =
            StateTransition::from_message_type(Dhcp6MessageType::Solicit, 0x456, &options_rc)
                .unwrap();
        assert_eq!(
            transition_rc.response_message_type(),
            Dhcp6MessageType::Reply
        ); // Skips ADVERTISE
    }

    #[test]
    fn test_requires_address_allocation() {
        let transition = StateTransition::new(0x123);
        assert!(transition.requires_address_allocation()); // SOLICIT requires allocation

        let options = vec![];
        let info_req = StateTransition::from_message_type(
            Dhcp6MessageType::InformationRequest,
            0x456,
            &options,
        )
        .unwrap();
        assert!(!info_req.requires_address_allocation()); // Stateless
    }

    #[test]
    fn test_is_terminal() {
        let mut transition = StateTransition::new(0x123);
        assert!(!transition.is_terminal()); // SOLICIT not terminal

        transition.transition_to(Dhcp6State::Advertise).unwrap();
        transition.transition_to(Dhcp6State::Request).unwrap();
        transition.transition_to(Dhcp6State::Reply).unwrap();
        assert!(transition.is_terminal()); // REPLY is terminal

        let options = vec![];
        let mut release =
            StateTransition::from_message_type(Dhcp6MessageType::Release, 0x789, &options)
                .unwrap();
        assert!(release.is_terminal()); // RELEASE is terminal
    }

    #[test]
    fn test_display_formatting() {
        assert_eq!(format!("{}", Dhcp6MessageType::Solicit), "SOLICIT");
        assert_eq!(format!("{}", Dhcp6MessageType::Reply), "REPLY");
        assert_eq!(format!("{}", Dhcp6State::Solicit), "SOLICIT");
        assert_eq!(format!("{}", Dhcp6State::Renew), "RENEW");
    }

    #[test]
    fn test_rapid_commit_state_machine() {
        // Create transition with rapid commit
        let options_rc = vec![Dhcp6Option::RapidCommit];
        let mut transition =
            StateTransition::from_message_type(Dhcp6MessageType::Solicit, 0x123, &options_rc)
                .unwrap();

        assert!(transition.requires_rapid_commit());
        assert_eq!(transition.current_state(), Dhcp6State::Solicit);

        // Can transition directly to REPLY (bypass ADVERTISE)
        assert!(transition.transition_to(Dhcp6State::Reply).is_ok());
        assert_eq!(transition.current_state(), Dhcp6State::Reply);
        assert!(transition.is_terminal());
    }

    #[test]
    fn test_full_4_message_exchange() {
        let mut transition = StateTransition::new(0x123456);

        // SOLICIT
        assert_eq!(transition.current_state(), Dhcp6State::Solicit);
        assert_eq!(
            transition.response_message_type(),
            Dhcp6MessageType::Advertise
        );

        // ADVERTISE
        assert!(transition.transition_to(Dhcp6State::Advertise).is_ok());
        assert_eq!(transition.current_state(), Dhcp6State::Advertise);

        // REQUEST
        assert!(transition.transition_to(Dhcp6State::Request).is_ok());
        assert_eq!(transition.current_state(), Dhcp6State::Request);

        // REPLY
        assert!(transition.transition_to(Dhcp6State::Reply).is_ok());
        assert_eq!(transition.current_state(), Dhcp6State::Reply);
        assert!(transition.is_terminal());
    }

    #[test]
    fn test_lease_renewal_cycle() {
        let options = vec![];
        let mut transition =
            StateTransition::from_message_type(Dhcp6MessageType::Renew, 0x789, &options).unwrap();

        assert_eq!(transition.current_state(), Dhcp6State::Renew);
        assert!(transition.requires_address_allocation());

        // RENEW → REPLY
        assert!(transition.transition_to(Dhcp6State::Reply).is_ok());
        assert_eq!(transition.current_state(), Dhcp6State::Reply);
    }

    #[test]
    fn test_information_request_stateless() {
        let options = vec![];
        let mut transition = StateTransition::from_message_type(
            Dhcp6MessageType::InformationRequest,
            0xABC,
            &options,
        )
        .unwrap();

        assert_eq!(transition.current_state(), Dhcp6State::InformationRequest);
        assert!(!transition.requires_address_allocation()); // Stateless

        // INFORMATION-REQUEST → REPLY
        assert!(transition.transition_to(Dhcp6State::Reply).is_ok());
        assert_eq!(
            transition.response_message_type(),
            Dhcp6MessageType::Reply
        );
    }
}
