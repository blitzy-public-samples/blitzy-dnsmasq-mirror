//! Runtime module providing daemon lifecycle management and event loop orchestration.
//!
//! This module replaces C's scattered lifecycle code across dnsmasq.c, poll.c, and helper.c
//! with a structured Rust module system. It orchestrates daemon initialization, privilege
//! management, signal handling, and the main async event loop using Tokio.
//!
//! # Architecture
//!
//! The runtime module eliminates C's manual fork/poll/signal patterns and replaces them with:
//! - **Tokio async runtime**: Replaces manual poll() event loop from poll.c
//! - **Structured signal handling**: Replaces self-pipe pattern with tokio::signal
//! - **Type-safe daemonization**: Replaces unsafe fork() calls with nix crate wrappers
//! - **Async process spawning**: Replaces blocking fork/exec with tokio::process
//!
//! # Components
//!
//! - [`event_loop`]: Main async event loop with tokio::select! multiplexing
//! - [`daemon`]: Daemonization, privilege dropping, and PID file management
//! - [`signal`]: Signal handler setup for SIGHUP, SIGUSR1, SIGTERM, etc.
//! - [`helpers`]: Process spawning for DHCP scripts and external commands
//!
//! # Example Usage
//!
//! ```ignore
//! use dnsmasq::runtime;
//! use dnsmasq::config::Config;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load configuration
//!     let config = Config::new();
//!     
//!     // Daemonize if requested (fork to background)
//!     runtime::daemonize(&config.daemon_config)?;
//!     
//!     // Drop privileges after binding to privileged ports
//!     runtime::drop_privileges(&config.privilege_config)?;
//!     
//!     // Create PID file for init script integration
//!     runtime::create_pid_file(&config.daemon_config.pid_file, None)?;
//!     
//!     // Set up signal handlers
//!     let signal_handler = runtime::setup_signal_handlers()?;
//!     
//!     // Spawn helper process for script execution
//!     let helper_handle = runtime::spawn_helper_process(&config, None, Default::default())?;
//!     
//!     // Create daemon state
//!     let state = Arc::new(RwLock::new(crate::types::DaemonState::new()));
//!     
//!     // Run main event loop until shutdown signal
//!     runtime::run_event_loop(config, state, signal_handler).await?;
//!     Ok(())
//! }
//! ```
//!
//! # Signal Handling
//!
//! The runtime module provides type-safe signal handling that replaces C's signal handlers:
//!
//! | C Signal | Rust SignalEvent | Purpose |
//! |----------|------------------|---------|
//! | SIGTERM/SIGINT | `SignalEvent::Terminate` | Graceful shutdown with lease flush |
//! | SIGHUP | `SignalEvent::Reload` | Reload configuration without restart |
//! | SIGUSR1 | `SignalEvent::DumpCache` | Dump DNS cache to logs |
//! | SIGUSR2 | `SignalEvent::ReopenLog` | Reopen log files for rotation |
//! | SIGALRM | `SignalEvent::TimeCheck` | Periodic timer events |
//! | SIGCHLD | `SignalEvent::ChildExited` | Helper process termination |
//!
//! # Error Handling
//!
//! All runtime operations return Result types with specific error variants:
//! - [`DaemonError`]: Daemonization, privilege dropping, PID file errors
//! - [`SignalError`]: Signal handler setup and delivery errors
//! - [`HelperError`]: Process spawning and communication errors
//!
//! # Compatibility Notes
//!
//! This module maintains backward compatibility with the C version:
//! - PID file format is identical for init script compatibility
//! - Signal handling behavior matches C version exactly
//! - Privilege dropping sequence (bind → drop) is preserved
//! - Exit codes match C version for script compatibility

// Module declarations - each corresponds to a separate .rs file in src/runtime/
pub mod event_loop;
pub mod daemon;
pub mod signal;
pub mod helpers;

// Primary runtime function re-exports for main.rs
pub use event_loop::run_event_loop;
pub use daemon::{daemonize, drop_privileges, create_pid_file};
pub use signal::setup_signal_handlers;
pub use helpers::spawn_helper_process;

// Type re-exports for configuration and state management
pub use event_loop::EventLoopHandle;
pub use daemon::{DaemonConfig, PrivilegeConfig};
pub use signal::{SignalEvent, SignalHandler};
pub use helpers::{ScriptEvent, HelperHandle};

// Error type re-exports for external error handling
pub use daemon::DaemonError;
pub use signal::SignalError;
pub use helpers::HelperError;

// Optional test utilities for integration testing
#[cfg(test)]
pub mod test_utils;

#[cfg(test)]
pub use test_utils::*;
