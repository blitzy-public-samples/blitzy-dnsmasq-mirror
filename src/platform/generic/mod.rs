//! Generic POSIX platform implementations
//!
//! This module provides fallback implementations for platforms that don't have
//! specific native implementations (Linux, BSD, macOS).

// Generic POSIX networking fallback
pub mod network;

// Re-export GenericPlatform
pub use network::GenericPlatform;
