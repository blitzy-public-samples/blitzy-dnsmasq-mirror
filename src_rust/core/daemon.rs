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
    pub fn new(config: crate::config::types::Config) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Run the daemon
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: Implement daemon runtime
        Ok(())
    }
}
