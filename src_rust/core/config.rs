//! Compile-time configuration constants
//!
//! This module replaces C's config.h with Rust const items.

/// Default DNS port
pub const DEFAULT_DNS_PORT: u16 = 53;

/// Default DHCP port
pub const DEFAULT_DHCP_PORT: u16 = 67;

/// Cache size
pub const CACHE_SIZE: usize = 150;

/// Forward table size
pub const FTABSIZE: usize = 150;
