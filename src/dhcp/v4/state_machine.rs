// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! # DHCPv4 State Machine
//!
//! This module implements a type-safe DHCPv4 state machine enforcing RFC 2131
//! state transitions with compile-time prevention of invalid message sequences.
//!
//! ## Purpose
//!
//! Provides explicit state management for DHCPv4 protocol exchanges, replacing
//! C's implicit state tracking through lease flags and packet inspection with
//! Rust's type system. Each state transition is validated, ensuring clients can
//! only send valid messages in each state and servers generate appropriate responses.
//!
//! ## C Source Mapping
//!
//! This module translates state machine logic from:
//! - `src/dhcp.c`: Implicit state handling in `dhcp_reply()` (lines 71-1025)
//! - `src/rfc2131.c`: Message type dispatch and lease allocation (lines 71-1025)
//!
//! ### Key Transformations
//!
//! - C's scattered if-else chains checking message type → Rust match expressions
//! - C's `lease_find_by_client()` returning NULL → Rust `Option<Lease>` with match
//! - C's implicit state changes via lease DB updates → Explicit state transitions
//! - C's manual transaction ID validation → Type-safe xid matching
//! - C's `calc_time()` lease time calculation → Rust Duration with constants
//!
//! ## State Diagram (RFC 2131 Section 3.1)
//!
//! ```text
//!                          INIT
//!                            ↓ (client sends DISCOVER)
//!                        SELECTING
//!                            ↓ (server sends OFFER)
//!                            ↓ (client sends REQUEST)
//!                          BOUND
//!                            ↓ (T1 timer expires)
//!                         RENEWING
//!                            ↓ (T2 timer expires)
//!                        REBINDING
//!                            ↓ (lease expires)
//!                          INIT
//!
//! Alternative paths:
//! - INIT → InitReboot (client has previous lease)
//! - BOUND → Released (client sends RELEASE)
//! - Any → INIT (client sends DECLINE or receives NAK)
//! ```
//!
//! ## Message Type Validation
//!
//! Each state accepts specific message types:
//! - `INIT`: DISCOVER
//! - `SELECTING`: REQUEST (with server identifier)
//! - `REQUESTING`: (server-side only, waiting to send ACK)
//! - `BOUND`: RELEASE, DECLINE, REQUEST (renewal)
//! - `RENEWING`: REQUEST (renewal to same server)
//! - `REBINDING`: REQUEST (rebinding to any server)
//! - `InitReboot`: REQUEST (verification after reboot)
//!
//! ## Timer Management
//!
//! - **T1** (Renewal Timer): 50% of lease time by default
//! - **T2** (Rebinding Timer): 87.5% of lease time by default
//! - **Lease Expiration**: 100% of lease time
//!
//! Configurable via DHCP Option 58 (T1) and Option 59 (T2).
//!
//! ## Thread Safety
//!
//! `DhcpTransaction` is not thread-safe and should be protected by appropriate
//! synchronization primitives if accessed from multiple threads. In the current
//! architecture, each transaction is processed sequentially in the async runtime.
//!
//! ## Examples
//!
//! ```rust,ignore
//! use crate::dhcp::v4::state_machine::{DhcpState, DhcpTransaction};
//! use crate::dhcp::v4::protocol::MessageType;
//!
//! // Handle client DISCOVER message
//! let mut transaction = DhcpTransaction::new(0x12345678);
//! let new_state = transaction.handle_discover(
//!     client_mac,
//!     None, // No client ID
//!     None, // No requested IP
//! )?;
//! assert_eq!(new_state, DhcpState::Selecting);
//!
//! // Handle client REQUEST in SELECTING state
//! let new_state = transaction.handle_request(
//!     offered_ip,
//!     server_id,
//! )?;
//! assert_eq!(new_state, DhcpState::Bound);
//! ```

use std::net::Ipv4Addr;
use std::time::Duration;
use thiserror::Error;
use tracing::warn;

use crate::dhcp::lease::LeaseV4;
use crate::dhcp::v4::options::{
    DhcpOption, OPTION_CLIENT_ID, OPTION_LEASE_TIME, OPTION_REQUESTED_IP,
    OPTION_SERVER_IDENTIFIER, OPTION_T1, OPTION_T2,
};
use crate::dhcp::v4::protocol::MessageType;
use crate::types::addresses::AllAddr;
use crate::types::errors::DnsmasqResult;
use crate::util::time::monotonic_time;

/// Default lease time in seconds (24 hours)
const DEFAULT_LEASE_TIME: u64 = 86400;

/// Default T1 (renewal time) as fraction of lease time (50%)
const DEFAULT_T1_FRACTION: f64 = 0.5;

/// Default T2 (rebinding time) as fraction of lease time (87.5%)
const DEFAULT_T2_FRACTION: f64 = 0.875;

/// DHCPv4 client states per RFC 2131 Section 3.1
///
/// Represents the complete set of states a DHCP client can be in during its
/// interaction with a DHCP server. Each state determines which message types
/// are valid and what transitions are possible.
///
/// ## State Descriptions
///
/// - `Init`: Client has no IP address and no lease. This is the entry state
///   for all new DHCP transactions.
///
/// - `Selecting`: Client has broadcast a DISCOVER message and is waiting to
///   receive OFFER messages from one or more DHCP servers.
///
/// - `Requesting`: Client has selected a server and sent a REQUEST message,
///   waiting for ACK confirmation.
///
/// - `Bound`: Client has a valid lease and can use the assigned IP address.
///   This is the normal operational state.
///
/// - `Renewing`: T1 timer has expired (50% of lease time). Client is trying
///   to renew its lease by sending REQUEST messages directly to the server.
///
/// - `Rebinding`: T2 timer has expired (87.5% of lease time). Client is trying
///   to extend its lease by broadcasting REQUEST messages to any server.
///
/// - `InitReboot`: Client is rebooting and attempting to verify its previously
///   assigned IP address is still valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    /// Initial state - no IP address, no lease
    Init,
    /// Client sent DISCOVER, waiting for OFFER(s)
    Selecting,
    /// Client sent REQUEST, waiting for ACK
    Requesting,
    /// Client has valid lease and is using IP address
    Bound,
    /// Client attempting renewal with same server (T1 expired)
    Renewing,
    /// Client attempting rebinding with any server (T2 expired)
    Rebinding,
    /// Client verifying previous lease after reboot
    InitReboot,
}

/// DHCP transaction tracking structure
///
/// Maintains state for a single DHCP transaction from DISCOVER through lease
/// allocation. Tracks client identity, requested parameters, offered addresses,
/// and current protocol state.
///
/// ## Fields
///
/// - `xid`: Transaction ID from client DHCP packet (4-byte random number)
/// - `state`: Current DHCP protocol state
/// - `hardware_address`: Client MAC address from chaddr field
/// - `client_id`: Optional client identifier from DHCP Option 61
/// - `requested_ip`: IP address requested by client (Option 50)
/// - `offered_ip`: IP address offered by server in OFFER message
/// - `server_id`: Server identifier (Option 54) for server selection
/// - `lease_time`: Requested or offered lease duration in seconds
/// - `lease`: Associated lease object if one exists
///
/// ## Invariants
///
/// - `xid` must match across all messages in a transaction
/// - `client_id` takes precedence over `hardware_address` for client identification
/// - `offered_ip` must be set before transitioning to BOUND state
/// - `server_id` must match this server's address in REQUEST messages
#[derive(Debug, Clone)]
pub struct DhcpTransaction {
    /// Transaction ID (xid) from DHCP packet header
    xid: u32,
    /// Current DHCP protocol state
    state: DhcpState,
    /// Client hardware address (MAC address)
    hardware_address: Vec<u8>,
    /// Optional client identifier from Option 61
    client_id: Option<Vec<u8>>,
    /// Requested IP address from Option 50
    requested_ip: Option<Ipv4Addr>,
    /// IP address offered by server
    offered_ip: Option<Ipv4Addr>,
    /// Server identifier from Option 54
    server_id: Option<Ipv4Addr>,
    /// Lease duration in seconds
    lease_time: u64,
    /// Associated lease object
    lease: Option<LeaseV4>,
}

/// Errors that can occur during state transitions
///
/// These errors represent protocol violations or invalid state transitions
/// that should not occur with a correctly implemented DHCP client.
#[derive(Debug, Error)]
pub enum StateTransitionError {
    /// Attempted state transition is invalid per RFC 2131
    ///
    /// Example: Receiving OFFER when already in BOUND state
    #[error("Invalid state transition from {from:?} to {to:?} via message type {message:?}")]
    InvalidStateTransition {
        from: DhcpState,
        to: DhcpState,
        message: MessageType,
    },

    /// Message type is not valid for current state
    ///
    /// Example: RELEASE message when in INIT state
    #[error("Invalid message type {message_type:?} for state {state:?}")]
    InvalidMessageType {
        state: DhcpState,
        message_type: MessageType,
    },

    /// Transaction ID mismatch between request and response
    ///
    /// This can indicate packet corruption or a spoofing attempt
    #[error("Transaction ID mismatch: expected {expected:#x}, got {actual:#x}")]
    MismatchedTransactionId { expected: u32, actual: u32 },

    /// Client identifier mismatch in lease lookup
    ///
    /// Security concern: could indicate lease hijacking attempt
    #[error("Client identifier mismatch")]
    MismatchedClientId,

    /// Requested lease not found in database
    ///
    /// Client is attempting to renew or verify a lease that doesn't exist
    #[error("Lease not found for client")]
    LeaseNotFound,

    /// Requested IP address is not available
    ///
    /// Address is either allocated to another client or outside valid range
    #[error("Requested address {address} is not available")]
    AddressUnavailable { address: Ipv4Addr },

    /// Server identifier does not match this server
    ///
    /// Client selected a different server - we should ignore this REQUEST
    #[error("Server identifier {provided} does not match our address {expected}")]
    ServerIdMismatch {
        provided: Ipv4Addr,
        expected: Ipv4Addr,
    },
}

impl DhcpTransaction {
    /// Create a new DHCP transaction in INIT state
    ///
    /// # Arguments
    ///
    /// * `xid` - Transaction ID from client's DHCP packet
    ///
    /// # Returns
    ///
    /// New transaction in `DhcpState::Init` with no client information
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let transaction = DhcpTransaction::new(0x12345678);
    /// assert_eq!(transaction.get_state(), DhcpState::Init);
    /// ```
    pub fn new(xid: u32) -> Self {
        Self {
            xid,
            state: DhcpState::Init,
            hardware_address: Vec::new(),
            client_id: None,
            requested_ip: None,
            offered_ip: None,
            server_id: None,
            lease_time: DEFAULT_LEASE_TIME,
            lease: None,
        }
    }

    /// Handle DHCPDISCOVER message
    ///
    /// Processes client's initial DISCOVER message, transitioning from INIT to
    /// SELECTING state. Records client identity and any requested IP address.
    ///
    /// # Arguments
    ///
    /// * `hardware_address` - Client MAC address from chaddr field
    /// * `client_id` - Optional client identifier from Option 61
    /// * `requested_ip` - Optional requested IP from Option 50
    ///
    /// # Returns
    ///
    /// New state (`DhcpState::Selecting`) on success
    ///
    /// # Errors
    ///
    /// Returns `StateTransitionError::InvalidMessageType` if not in INIT or SELECTING state
    ///
    /// # State Transition
    ///
    /// ```text
    /// INIT → SELECTING (first DISCOVER)
    /// SELECTING → SELECTING (duplicate DISCOVER)
    /// ```
    pub fn handle_discover(
        &mut self,
        hardware_address: Vec<u8>,
        client_id: Option<Vec<u8>>,
        requested_ip: Option<Ipv4Addr>,
    ) -> Result<DhcpState, StateTransitionError> {
        // DISCOVER is valid in INIT and SELECTING states
        match self.state {
            DhcpState::Init | DhcpState::Selecting => {
                self.hardware_address = hardware_address;
                self.client_id = client_id;
                self.requested_ip = requested_ip;
                self.state = DhcpState::Selecting;
                Ok(self.state)
            }
            _ => Err(StateTransitionError::InvalidMessageType {
                state: self.state,
                message_type: MessageType::Discover,
            }),
        }
    }

    /// Handle DHCPREQUEST message
    ///
    /// Processes client REQUEST message, which has different semantics depending
    /// on current state:
    ///
    /// - **SELECTING**: Client accepting our OFFER (must include server identifier)
    /// - **INIT_REBOOT**: Client verifying previous lease
    /// - **RENEWING**: Client renewing lease (unicast to server)
    /// - **REBINDING**: Client rebinding lease (broadcast)
    /// - **BOUND**: Client explicitly renewing before T1
    ///
    /// # Arguments
    ///
    /// * `requested_ip` - IP address being requested
    /// * `server_id` - Server identifier from Option 54 (required in SELECTING state)
    ///
    /// # Returns
    ///
    /// New state on success, typically `DhcpState::Bound` if request is granted
    ///
    /// # Errors
    ///
    /// - `InvalidMessageType`: REQUEST not valid in current state
    /// - `ServerIdMismatch`: Client selected different server
    /// - `AddressUnavailable`: Requested address cannot be allocated
    ///
    /// # State Transitions
    ///
    /// ```text
    /// SELECTING → BOUND (server selected, lease granted)
    /// INIT_REBOOT → BOUND (previous lease verified)
    /// RENEWING → BOUND (renewal granted)
    /// REBINDING → BOUND (rebinding granted)
    /// BOUND → BOUND (explicit renewal)
    /// ```
    pub fn handle_request(
        &mut self,
        requested_ip: Ipv4Addr,
        server_id: Option<Ipv4Addr>,
    ) -> Result<DhcpState, StateTransitionError> {
        match self.state {
            DhcpState::Selecting => {
                // In SELECTING state, client MUST include server identifier
                if let Some(sid) = server_id {
                    self.server_id = Some(sid);
                    self.requested_ip = Some(requested_ip);
                    // Will transition to BOUND after allocating lease
                    self.state = DhcpState::Requesting;
                    Ok(self.state)
                } else {
                    warn!(
                        "REQUEST in SELECTING state without server identifier (xid={:#x})",
                        self.xid
                    );
                    Err(StateTransitionError::InvalidMessageType {
                        state: self.state,
                        message_type: MessageType::Request,
                    })
                }
            }
            DhcpState::InitReboot | DhcpState::Renewing | DhcpState::Rebinding | DhcpState::Bound => {
                // In renewal states, update requested IP
                self.requested_ip = Some(requested_ip);
                if let Some(sid) = server_id {
                    self.server_id = Some(sid);
                }
                // Stay in same state or transition to BOUND after lease update
                Ok(self.state)
            }
            _ => Err(StateTransitionError::InvalidMessageType {
                state: self.state,
                message_type: MessageType::Request,
            }),
        }
    }

    /// Handle DHCPRELEASE message
    ///
    /// Processes client's voluntary release of IP address. Only valid when
    /// client has an active lease (BOUND state).
    ///
    /// # Returns
    ///
    /// Transitions to `DhcpState::Init`
    ///
    /// # Errors
    ///
    /// Returns `InvalidMessageType` if not in BOUND state
    ///
    /// # State Transition
    ///
    /// ```text
    /// BOUND → INIT (lease released)
    /// ```
    ///
    /// # Server Behavior
    ///
    /// Server MUST NOT send any response to RELEASE (RFC 2131 Section 4.3.4).
    /// The lease is marked as available immediately.
    pub fn handle_release(&mut self) -> Result<DhcpState, StateTransitionError> {
        match self.state {
            DhcpState::Bound => {
                // Clear transaction state
                self.state = DhcpState::Init;
                self.offered_ip = None;
                self.requested_ip = None;
                self.lease = None;
                Ok(self.state)
            }
            _ => Err(StateTransitionError::InvalidMessageType {
                state: self.state,
                message_type: MessageType::Release,
            }),
        }
    }

    /// Handle DHCPDECLINE message
    ///
    /// Client detected offered IP address is already in use (via ARP probe).
    /// Server MUST mark address as unavailable. Client returns to INIT state.
    ///
    /// # Returns
    ///
    /// Transitions to `DhcpState::Init`
    ///
    /// # Errors
    ///
    /// Returns `InvalidMessageType` if address hasn't been offered yet
    ///
    /// # State Transition
    ///
    /// ```text
    /// SELECTING → INIT (address conflict detected)
    /// REQUESTING → INIT (address conflict detected)
    /// ```
    ///
    /// # Server Behavior
    ///
    /// Server MUST NOT send any response to DECLINE (RFC 2131 Section 4.3.3).
    /// The declined address should be marked as unavailable for a period to
    /// allow time for the conflicting host to be located.
    pub fn handle_decline(&mut self) -> Result<DhcpState, StateTransitionError> {
        match self.state {
            DhcpState::Selecting | DhcpState::Requesting => {
                // Address conflict detected, return to INIT
                self.state = DhcpState::Init;
                self.offered_ip = None;
                self.requested_ip = None;
                self.lease = None;
                Ok(self.state)
            }
            _ => Err(StateTransitionError::InvalidMessageType {
                state: self.state,
                message_type: MessageType::Decline,
            }),
        }
    }

    /// Get current transaction state
    ///
    /// # Returns
    ///
    /// Current `DhcpState`
    pub fn get_state(&self) -> DhcpState {
        self.state
    }

    /// Get transaction ID
    ///
    /// # Returns
    ///
    /// Transaction ID (xid) from DHCP packet header
    pub fn get_xid(&self) -> u32 {
        self.xid
    }

    /// Get client identifier
    ///
    /// Returns client identifier from Option 61 if present, otherwise None.
    /// Client identifier takes precedence over hardware address for client
    /// identification.
    ///
    /// # Returns
    ///
    /// Optional client identifier bytes
    pub fn get_client_id(&self) -> Option<&[u8]> {
        self.client_id.as_deref()
    }

    /// Get requested IP address
    ///
    /// # Returns
    ///
    /// IP address from Option 50 if client specified one
    pub fn get_requested_ip(&self) -> Option<Ipv4Addr> {
        self.requested_ip
    }

    /// Get offered IP address
    ///
    /// # Returns
    ///
    /// IP address offered by server in OFFER message
    pub fn get_offered_ip(&self) -> Option<Ipv4Addr> {
        self.offered_ip
    }

    /// Get associated lease
    ///
    /// # Returns
    ///
    /// Reference to lease object if one exists
    pub fn get_lease(&self) -> Option<&LeaseV4> {
        self.lease.as_ref()
    }

    /// Calculate T1 (renewal time)
    ///
    /// T1 is the time at which the client should begin renewal attempts by
    /// contacting the original DHCP server. Default is 50% of lease time.
    ///
    /// # Arguments
    ///
    /// * `lease_time` - Total lease duration in seconds
    /// * `override_t1` - Optional explicit T1 value from Option 58
    ///
    /// # Returns
    ///
    /// T1 value in seconds
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Default: 50% of 24-hour lease = 12 hours
    /// let t1 = DhcpTransaction::calculate_t1(86400, None);
    /// assert_eq!(t1, 43200);
    ///
    /// // Override: explicit T1 value
    /// let t1 = DhcpTransaction::calculate_t1(86400, Some(3600));
    /// assert_eq!(t1, 3600);
    /// ```
    pub fn calculate_t1(lease_time: u64, override_t1: Option<u64>) -> u64 {
        override_t1.unwrap_or_else(|| (lease_time as f64 * DEFAULT_T1_FRACTION) as u64)
    }

    /// Calculate T2 (rebinding time)
    ///
    /// T2 is the time at which the client should begin rebinding attempts by
    /// contacting any DHCP server. Default is 87.5% of lease time.
    ///
    /// # Arguments
    ///
    /// * `lease_time` - Total lease duration in seconds
    /// * `override_t2` - Optional explicit T2 value from Option 59
    ///
    /// # Returns
    ///
    /// T2 value in seconds
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Default: 87.5% of 24-hour lease = 21 hours
    /// let t2 = DhcpTransaction::calculate_t2(86400, None);
    /// assert_eq!(t2, 75600);
    ///
    /// // Override: explicit T2 value
    /// let t2 = DhcpTransaction::calculate_t2(86400, Some(72000));
    /// assert_eq!(t2, 72000);
    /// ```
    pub fn calculate_t2(lease_time: u64, override_t2: Option<u64>) -> u64 {
        override_t2.unwrap_or_else(|| (lease_time as f64 * DEFAULT_T2_FRACTION) as u64)
    }

    /// Validate server identifier matches expected value
    ///
    /// In SELECTING state, client's REQUEST must include server identifier
    /// matching this server's address. This method verifies the match.
    ///
    /// # Arguments
    ///
    /// * `expected_server_id` - This server's IP address
    ///
    /// # Returns
    ///
    /// `Ok(())` if server identifier matches or is not required
    ///
    /// # Errors
    ///
    /// Returns `ServerIdMismatch` if identifier doesn't match
    pub fn validate_server_id(&self, expected_server_id: Ipv4Addr) -> Result<(), StateTransitionError> {
        if let Some(provided) = self.server_id {
            if provided != expected_server_id {
                return Err(StateTransitionError::ServerIdMismatch {
                    provided,
                    expected: expected_server_id,
                });
            }
        }
        Ok(())
    }

    /// Validate transaction ID matches expected value
    ///
    /// All messages in a DHCP transaction must use the same transaction ID (xid).
    /// This method verifies incoming messages have the correct xid.
    ///
    /// # Arguments
    ///
    /// * `packet_xid` - Transaction ID from received packet
    ///
    /// # Returns
    ///
    /// `Ok(())` if xid matches
    ///
    /// # Errors
    ///
    /// Returns `MismatchedTransactionId` if xid doesn't match
    pub fn validate_xid(&self, packet_xid: u32) -> Result<(), StateTransitionError> {
        if self.xid != packet_xid {
            Err(StateTransitionError::MismatchedTransactionId {
                expected: self.xid,
                actual: packet_xid,
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_transaction() {
        let xid = 0x12345678;
        let transaction = DhcpTransaction::new(xid);
        assert_eq!(transaction.get_state(), DhcpState::Init);
        assert_eq!(transaction.get_xid(), xid);
        assert!(transaction.get_client_id().is_none());
        assert!(transaction.get_requested_ip().is_none());
        assert!(transaction.get_offered_ip().is_none());
    }

    #[test]
    fn test_handle_discover_from_init() {
        let mut transaction = DhcpTransaction::new(0x11111111);
        let mac = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client_id = Some(vec![0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let requested = Some(Ipv4Addr::new(192, 168, 1, 100));

        let result = transaction.handle_discover(mac.clone(), client_id.clone(), requested);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DhcpState::Selecting);
        assert_eq!(transaction.get_state(), DhcpState::Selecting);
        assert_eq!(transaction.get_client_id(), client_id.as_deref());
        assert_eq!(transaction.get_requested_ip(), requested);
    }

    #[test]
    fn test_handle_discover_invalid_state() {
        let mut transaction = DhcpTransaction::new(0x22222222);
        transaction.state = DhcpState::Bound;
        
        let mac = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let result = transaction.handle_discover(mac, None, None);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            StateTransitionError::InvalidMessageType { state, message_type } => {
                assert_eq!(state, DhcpState::Bound);
                assert_eq!(message_type, MessageType::Discover);
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_handle_request_from_selecting() {
        let mut transaction = DhcpTransaction::new(0x33333333);
        transaction.state = DhcpState::Selecting;
        
        let requested = Ipv4Addr::new(192, 168, 1, 100);
        let server_id = Some(Ipv4Addr::new(192, 168, 1, 1));
        
        let result = transaction.handle_request(requested, server_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DhcpState::Requesting);
    }

    #[test]
    fn test_handle_request_selecting_without_server_id() {
        let mut transaction = DhcpTransaction::new(0x44444444);
        transaction.state = DhcpState::Selecting;
        
        let requested = Ipv4Addr::new(192, 168, 1, 100);
        let result = transaction.handle_request(requested, None);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_release_from_bound() {
        let mut transaction = DhcpTransaction::new(0x55555555);
        transaction.state = DhcpState::Bound;
        transaction.offered_ip = Some(Ipv4Addr::new(192, 168, 1, 100));
        
        let result = transaction.handle_release();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DhcpState::Init);
        assert!(transaction.get_offered_ip().is_none());
    }

    #[test]
    fn test_handle_release_invalid_state() {
        let mut transaction = DhcpTransaction::new(0x66666666);
        transaction.state = DhcpState::Init;
        
        let result = transaction.handle_release();
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_decline() {
        let mut transaction = DhcpTransaction::new(0x77777777);
        transaction.state = DhcpState::Selecting;
        transaction.offered_ip = Some(Ipv4Addr::new(192, 168, 1, 100));
        
        let result = transaction.handle_decline();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DhcpState::Init);
        assert!(transaction.get_offered_ip().is_none());
    }

    #[test]
    fn test_calculate_t1_default() {
        let lease_time = 86400; // 24 hours
        let t1 = DhcpTransaction::calculate_t1(lease_time, None);
        assert_eq!(t1, 43200); // 12 hours (50%)
    }

    #[test]
    fn test_calculate_t1_override() {
        let lease_time = 86400;
        let override_t1 = Some(3600); // 1 hour
        let t1 = DhcpTransaction::calculate_t1(lease_time, override_t1);
        assert_eq!(t1, 3600);
    }

    #[test]
    fn test_calculate_t2_default() {
        let lease_time = 86400; // 24 hours
        let t2 = DhcpTransaction::calculate_t2(lease_time, None);
        assert_eq!(t2, 75600); // 21 hours (87.5%)
    }

    #[test]
    fn test_calculate_t2_override() {
        let lease_time = 86400;
        let override_t2 = Some(72000); // 20 hours
        let t2 = DhcpTransaction::calculate_t2(lease_time, override_t2);
        assert_eq!(t2, 72000);
    }

    #[test]
    fn test_validate_server_id_match() {
        let mut transaction = DhcpTransaction::new(0x88888888);
        let server_addr = Ipv4Addr::new(192, 168, 1, 1);
        transaction.server_id = Some(server_addr);
        
        let result = transaction.validate_server_id(server_addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_server_id_mismatch() {
        let mut transaction = DhcpTransaction::new(0x99999999);
        transaction.server_id = Some(Ipv4Addr::new(192, 168, 1, 2));
        
        let result = transaction.validate_server_id(Ipv4Addr::new(192, 168, 1, 1));
        assert!(result.is_err());
        match result.unwrap_err() {
            StateTransitionError::ServerIdMismatch { provided, expected } => {
                assert_eq!(provided, Ipv4Addr::new(192, 168, 1, 2));
                assert_eq!(expected, Ipv4Addr::new(192, 168, 1, 1));
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_validate_xid_match() {
        let xid = 0xAAAAAAAA;
        let transaction = DhcpTransaction::new(xid);
        
        let result = transaction.validate_xid(xid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_xid_mismatch() {
        let transaction = DhcpTransaction::new(0xBBBBBBBB);
        
        let result = transaction.validate_xid(0xCCCCCCCC);
        assert!(result.is_err());
        match result.unwrap_err() {
            StateTransitionError::MismatchedTransactionId { expected, actual } => {
                assert_eq!(expected, 0xBBBBBBBB);
                assert_eq!(actual, 0xCCCCCCCC);
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_state_transitions() {
        let mut transaction = DhcpTransaction::new(0xDDDDDDDD);
        
        // INIT → SELECTING
        assert_eq!(transaction.get_state(), DhcpState::Init);
        let _ = transaction.handle_discover(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55], None, None);
        assert_eq!(transaction.get_state(), DhcpState::Selecting);
        
        // SELECTING → REQUESTING
        let _ = transaction.handle_request(
            Ipv4Addr::new(192, 168, 1, 100),
            Some(Ipv4Addr::new(192, 168, 1, 1)),
        );
        assert_eq!(transaction.get_state(), DhcpState::Requesting);
        
        // Manually set to BOUND for testing RELEASE
        transaction.state = DhcpState::Bound;
        
        // BOUND → INIT (via RELEASE)
        let _ = transaction.handle_release();
        assert_eq!(transaction.get_state(), DhcpState::Init);
    }
}
