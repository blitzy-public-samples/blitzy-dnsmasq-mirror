//! Test utilities for runtime module
//!
//! This module provides helper functions and mocks for testing the runtime subsystem.

use super::*;
use std::time::Duration;

/// Create a test DaemonConfig with reasonable defaults
pub fn test_daemon_config() -> DaemonConfig {
    DaemonConfig {
        daemonize: false,
        debug: true,
        pid_file: None,
    }
}

/// Create a test PrivilegeConfig for non-root testing
pub fn test_privilege_config() -> PrivilegeConfig {
    PrivilegeConfig {
        user: None,
        group: None,
        drop_after_bind: true,
    }
}

/// Helper to wait for a signal with timeout
pub async fn wait_for_signal_with_timeout(
    handler: &mut SignalHandler,
    timeout: Duration,
) -> Option<SignalEvent> {
    tokio::time::timeout(timeout, handler.recv())
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_config_creation() {
        let config = test_daemon_config();
        assert!(!config.daemonize);
        assert!(config.debug);
    }

    #[test]
    fn test_privilege_config_creation() {
        let config = test_privilege_config();
        assert!(config.user.is_none());
        assert!(config.group.is_none());
        assert!(config.drop_after_bind);
    }
}
