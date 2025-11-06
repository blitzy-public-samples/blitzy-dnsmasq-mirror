//! Linux-specific platform implementations
//!
//! This module contains Linux-specific features such as netlink, inotify,
//! ipset, nftables, and connection tracking integration.

// Netlink socket interface for network monitoring
pub mod netlink;

// Re-export LinuxPlatform for use by parent module
pub use netlink::LinuxPlatform;

// Connection tracking integration
#[cfg(feature = "conntrack")]
pub mod conntrack;

// inotify file system monitoring
#[cfg(feature = "inotify")]
pub mod inotify;

// ipset integration
#[cfg(feature = "ipset")]
pub mod ipset;

// nftables set manipulation
#[cfg(feature = "nftables")]
pub mod nftset;
