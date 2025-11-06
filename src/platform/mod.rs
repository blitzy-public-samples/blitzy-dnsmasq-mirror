//! Platform-specific implementations
//!
//! This module provides platform-specific functionality for Linux, BSD, macOS,
//! and other operating systems.

// Linux-specific implementations
#[cfg(target_os = "linux")]
pub mod linux;

// BSD-specific implementations (FreeBSD, OpenBSD, NetBSD, DragonFly BSD, macOS)
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
pub mod bsd;
