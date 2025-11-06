//! Linux-specific platform implementations
//!
//! This module contains Linux-specific features such as netlink, inotify,
//! ipset, nftables, and connection tracking integration.

// nftables set manipulation
#[cfg(feature = "nftables")]
pub mod nftset;
