//! Logging infrastructure
//!
//! This module provides structured logging capabilities for dnsmasq,
//! supporting both JSON and plain text formats for operational flexibility.

pub mod structured;

pub use structured::{JsonFormatter, LogFormat, PlainTextFormatter};

/// Initialize logging subsystem
///
/// Sets up the tracing subscriber with default configuration.
/// For custom formatting (JSON or plain text), use the formatters
/// from the `structured` module directly.
///
/// # Returns
///
/// `Ok(())` on success, `Err` if initialization fails
///
/// # Examples
///
/// ```
/// use dnsmasq::logging;
///
/// logging::init().expect("Failed to initialize logging");
/// ```
///
/// # Errors
///
/// Currently returns `Ok` in all cases. Future implementation may return errors
/// if logging initialization fails.
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    Ok(())
}
