//! Linux-specific platform implementations
//!
//! This module contains Linux-specific features such as netlink, inotify,
//! ipset, nftables, and connection tracking integration.

// inotify file system monitoring
#[cfg(feature = "inotify")]
pub mod inotify;

// ipset integration
#[cfg(feature = "ipset")]
pub mod ipset;

// nftables set manipulation
#[cfg(feature = "nftables")]
pub mod nftset;
