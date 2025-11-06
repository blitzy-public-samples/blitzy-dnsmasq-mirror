//! DNS subsystem
//!
//! DNS protocol handling, parsing, caching, and forwarding.

pub mod protocol;
pub mod parser;
pub mod cache;
pub mod forwarder;

#[cfg(feature = "dnssec")]
pub mod dnssec;
