//! Main daemon structure
//!
//! This module defines the main Daemon struct that holds all runtime state.

use std::sync::Arc;
use tokio::sync::RwLock;

/// Main daemon structure
///
/// This replaces the global `struct daemon` from C's dnsmasq.h
pub struct Daemon {
    /// Configuration
    pub config: Arc<RwLock<crate::config::types::Config>>,
}

impl Daemon {
    /// Create a new daemon instance
    #[must_use]
    pub fn new(config: crate::config::types::Config) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Run the daemon
    ///
    /// # Errors
    ///
    /// Returns an error if the daemon fails to initialize or encounters a fatal runtime error
    #[allow(clippy::unused_async)] // Async for future implementation
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: Implement daemon runtime
        Ok(())
    }
}
