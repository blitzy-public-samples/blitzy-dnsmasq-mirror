//! Platform-specific implementations
//!
//! This module provides platform-specific functionality for Linux, BSD, macOS,
//! and other operating systems.

// Linux-specific implementations
#[cfg(target_os = "linux")]
pub mod linux;
