//! BSD-specific platform implementations
//!
//! This module contains BSD-specific features including kqueue file system monitoring
//! for FreeBSD, OpenBSD, NetBSD, DragonFly BSD, and macOS platforms.

// kqueue-based file system monitoring
pub mod kqueue;
