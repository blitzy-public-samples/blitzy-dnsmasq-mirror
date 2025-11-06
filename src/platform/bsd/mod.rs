//! BSD-specific platform implementations
//!
//! This module contains BSD-specific features including kqueue file system monitoring
//! for FreeBSD, OpenBSD, NetBSD, DragonFly BSD, and macOS platforms.

// Berkeley Packet Filter interface for network operations
pub mod bpf;

// Re-export BsdPlatform for use by parent module
pub use bpf::BsdPlatform;

// kqueue-based file system monitoring
pub mod kqueue;
