//! DHCP subsystem
//!
//! DHCPv4 and DHCPv6 server implementations.

// Common utilities shared by DHCPv4 and DHCPv6
pub mod common;

#[cfg(feature = "dhcp")]
pub mod v4;

#[cfg(feature = "dhcp6")]
pub mod v6;
