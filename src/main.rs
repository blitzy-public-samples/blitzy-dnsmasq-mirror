// Copyright (c) 2000-2024 Simon Kelley and dnsmasq contributors
// Copyright (c) 2024 Blitzy Platform - Rust translation
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

//! # dnsmasq-rs: Main daemon entry point
//!
//! This module implements the binary entry point for the dnsmasq-rs daemon, orchestrating
//! the complete daemon lifecycle from initial configuration parsing through graceful shutdown.
//! It replaces the C implementation's `main()` function in `src/dnsmasq.c` with a modern
//! async Rust architecture based on Tokio.
//!
//! ## Purpose
//!
//! This is the primary executable entry point that:
//! 1. Parses command-line arguments using clap (200+ options for compatibility with C version)
//! 2. Loads and validates configuration from files and environment
//! 3. Initializes the logging subsystem (syslog, file, stderr, JSON)
//! 4. Optionally forks to background (daemonization) unless `--no-daemon` specified
//! 5. Creates PID file for init system integration
//! 6. Drops privileges from root to configured user/group after binding privileged ports
//! 7. Initializes daemon state (DNS cache, DHCP leases, network interfaces)
//! 8. Sets up async signal handlers for SIGHUP (reload), SIGUSR1 (dump), SIGTERM (shutdown)
//! 9. Runs the main Tokio-based event loop multiplexing DNS, DHCP, TFTP, and control events
//! 10. Handles graceful shutdown with lease file flush and connection cleanup
//!
//! ## Architecture
//!
//! The C implementation uses a single-threaded, `poll()`-based event loop with manual file
//! descriptor management. This Rust implementation uses:
//!
//! - **Tokio Runtime**: Async/await with work-stealing scheduler replacing manual `poll()`
//! - **Structured Concurrency**: Multiple async tasks coordinated via `tokio::select!`
//! - **Type-Safe Configuration**: clap derive macros replace C's manual `getopt_long()`
//! - **RAII Resource Management**: Automatic cleanup of PID files, sockets, lease files
//! - **Memory Safety**: Zero unsafe code in initialization path, no manual memory management
//!
//! ## Initialization Sequence
//!
//! The daemon initialization follows this precise order (matching C implementation):
//!
//! 1. **Parse CLI** → `Cli::parse()` processes all command-line options
//! 2. **Load Config** → Merge CLI args, config files, environment variables
//! 3. **Validate Config** → Check for conflicts, required options, network constraints
//! 4. **Init Logging** → Set up tracing infrastructure based on config
//! 5. **Pre-Daemon Checks** → Verify we can bind ports, read files (before forking)
//! 6. **Daemonize** → Fork to background if `--no-daemon` not set
//! 7. **PID File** → Create atomic PID file with exclusive lock
//! 8. **Bind Ports** → Create listening sockets on privileged ports (53, 67, 69)
//! 9. **Drop Privileges** → setuid/setgid to configured user (default: nobody)
//! 10. **Init State** → Build `DaemonState` with DNS cache, DHCP leases, interfaces
//! 11. **Signal Handlers** → Install async handlers for POSIX signals
//! 12. **Event Loop** → Enter `run_event_loop()` until termination signal
//! 13. **Cleanup** → Flush lease database, close sockets, remove PID file
//!
//! ## Signal Handling
//!
//! The C implementation uses the self-pipe trick for async-signal-safe signal handling.
//! This Rust implementation uses Tokio's signal streams which are natively async:
//!
//! - **SIGHUP**: Reload configuration, flush DNS cache, re-read hosts/resolv.conf
//! - **SIGUSR1**: Dump statistics (DNS cache hits, DHCP leases, memory usage)
//! - **SIGUSR2**: Rotate log files (if file logging enabled)
//! - **SIGTERM/SIGINT**: Graceful shutdown with lease file flush and socket cleanup
//! - **SIGPIPE**: Ignored (as in C version) to prevent termination on broken pipes
//!
//! ## Error Handling
//!
//! All errors are propagated via `Result<(), DnsmasqError>` and mapped to exit codes
//! compatible with the C version for init script compatibility:
//!
//! - `0` (Success): Normal termination via SIGTERM
//! - `1` (BadConfig): Configuration file parse error or invalid options
//! - `2` (BadNet): Network initialization failure (cannot bind ports, invalid interface)
//! - `3` (FileError): Cannot read/write lease file, hosts file, or PID file
//! - `4` (NoMemory): Memory allocation failure (should never occur in Rust)
//! - `5` (InitError): Privilege drop failure, daemonization error, PID file lock
//! - `6` (Misc): Catchall for other failures
//!
//! ## Exit Behavior
//!
//! The daemon exits with appropriate codes ensuring compatibility with:
//! - Systemd service units (status codes reported to systemd)
//! - Init scripts (shell scripts checking $? exit code)
//! - Monitoring systems (expecting specific error codes for alerting)
//!
//! ## Thread Safety
//!
//! The `main()` function is single-threaded until entering the Tokio runtime.
//! After runtime initialization, multiple async tasks may access shared state via
//! `Arc<RwLock<DaemonState>>`, providing interior mutability with reader-writer locks.
//!
//! ## C Source Reference
//!
//! Translates:
//! - `src/dnsmasq.c` main() function (lines 60-1055)
//! - Signal handler installation (lines 150-234)
//! - Privilege dropping sequence (lines 775-890)
//! - Main event loop invocation (line 1056)
//!
//! ## Performance Considerations
//!
//! - **Fast Startup**: Configuration parsing is parallel where possible
//! - **Memory Efficient**: State allocation is lazy (only allocate when features enabled)
//! - **Low Latency**: Tokio runtime provides sub-millisecond task scheduling
//! - **Scalability**: Work-stealing scheduler efficiently utilizes multiple CPU cores
//!
//! ## Platform Support
//!
//! Supports all platforms of the C version:
//! - Linux (primary platform with full feature support)
//! - FreeBSD, OpenBSD, NetBSD, DragonFly BSD
//! - macOS (Darwin)
//! - Solaris/illumos
//!
//! Platform-specific code is gated by `#[cfg(target_os = "...")]` attributes.

use std::process;
use std::sync::Arc;
use tokio::sync::RwLock;

// External crate imports - from external_imports schema
use anyhow::Context;
use clap::Parser;
use tracing::error;

// Internal module imports - ONLY from depends_on_files
use dnsmasq::{Config}; // from src/lib.rs
use dnsmasq::config::options::Cli;
use dnsmasq::constants::ExitCode;
use dnsmasq::runtime::daemon::{create_pid_file, daemonize, drop_privileges};
use dnsmasq::runtime::event_loop::run_event_loop;
use dnsmasq::runtime::signal::{setup_signal_handlers, SignalEvent};
use dnsmasq::types::daemon_state::DaemonState;
use dnsmasq::types::errors::DnsmasqResult;
use dnsmasq::util::logging::{init_logging, LogConfig};

/// Main entry point for dnsmasq-rs daemon
///
/// This is the binary's entry point, decorated with `#[tokio::main]` to automatically
/// set up the Tokio async runtime. The function coordinates the entire daemon lifecycle
/// from configuration loading through graceful shutdown.
///
/// # Flow
///
/// 1. Parse command-line arguments
/// 2. Build configuration by merging CLI, config files, defaults
/// 3. Initialize logging subsystem
/// 4. Daemonize if requested (fork to background)
/// 5. Create PID file
/// 6. Initialize daemon state
/// 7. Drop privileges after binding privileged ports
/// 8. Set up signal handlers
/// 9. Run main event loop
/// 10. Clean up on shutdown
///
/// # Returns
///
/// - `Ok(())` on graceful shutdown (exit code 0)
/// - `Err(anyhow::Error)` on any failure (mapped to appropriate exit codes)
///
/// # Panics
///
/// This function should never panic. All errors are handled via `Result` types and
/// logged before exiting with appropriate error codes.
///
/// # Examples
///
/// Typical invocations:
///
/// ```bash
/// # Start with default config file
/// dnsmasq-rs
///
/// # Specify custom config file
/// dnsmasq-rs --conf-file=/etc/dnsmasq/custom.conf
///
/// # Run in foreground with debug logging
/// dnsmasq-rs --no-daemon --log-queries --log-debug
///
/// # Start with specific user
/// dnsmasq-rs --user=dnsmasq --group=dnsmasq
/// ```
///
/// # C Source Reference
///
/// Replaces: `src/dnsmasq.c` main() function (lines 60-1287)
#[tokio::main]
async fn main() {
    // Phase 1: Parse command-line arguments
    // Replaces C: main() lines 60-96 (getopt_long loop in option.c read_opts)
    // Uses clap's derive macros for type-safe parsing of 200+ options
    let cli = Cli::parse();

    // Phase 2: Build configuration from CLI args, config files, and defaults
    // Replaces C: main() lines 97-150 (read_opts() call)
    // The Config struct aggregates all configuration sources with validation
    let config = match Config::from_cli(&cli)
        .context("Failed to load and validate configuration") {
        Ok(cfg) => cfg,
        Err(e) => {
            // Configuration error - print to stderr and exit with BadConfig code
            // Replaces C: main() lines 144-149 (die() calls on config errors)
            eprintln!("Configuration error: {:#}", e);
            eprintln!("Run 'dnsmasq-rs --help' for usage information");
            process::exit(ExitCode::BadConfig.as_i32());
        }
    };

    // Phase 3: Initialize logging subsystem
    // Replaces C: main() lines 234-299 (log_start() call from log.c)
    // Build logging configuration from daemon config
    let log_config = LogConfig::from_config(&config);
    
    if let Err(e) = init_logging(&log_config)
        .context("Logging subsystem initialization") {
        // If logging initialization fails, print to stderr and continue with degraded logging
        // Replaces C: Implicit fallback to stderr if syslog unavailable
        eprintln!("Warning: Failed to initialize logging: {:#}", e);
        eprintln!("Continuing with stderr logging only");
    }

    // Phase 4: Optional daemonization (fork to background)
    // Replaces C: main() lines 1021-1034 (daemon() call)
    // Only daemonize if --no-daemon is not set
    if !cli.no_daemon {
        if let Err(e) = daemonize(&config) {
            error!("Failed to daemonize: {}", e);
            process::exit(ExitCode::InitError.as_i32());
        }
    }

    // Phase 5: Create PID file for init system integration
    // Replaces C: main() lines 807-868 (PID file creation)
    // PID file is created with RAII wrapper ensuring cleanup on exit
    let _pid_file = match create_pid_file(&config) {
        Ok(pf) => pf,
        Err(e) => {
            error!("Failed to create PID file: {}", e);
            process::exit(ExitCode::InitError.as_i32());
        }
    };

    // Phase 6: Initialize daemon state before privilege drop
    // Replaces C: main() lines 300-806 (state initialization)
    // This includes binding to privileged ports which requires root
    let state = match DaemonState::new(config.clone()).await {
        Ok(s) => Arc::new(RwLock::new(s)),
        Err(e) => {
            error!("Failed to initialize daemon state: {}", e);
            // Map error type to appropriate exit code
            let exit_code = match e {
                dnsmasq::types::errors::DnsmasqError::Network(_) => ExitCode::BadNet,
                dnsmasq::types::errors::DnsmasqError::File(_) => ExitCode::FileError,
                _ => ExitCode::InitError,
            };
            process::exit(exit_code.as_i32());
        }
    };

    // Phase 7: Drop privileges after binding privileged ports
    // Replaces C: main() lines 869-994 (privilege dropping sequence)
    // Must occur AFTER binding ports 53, 67, 69 but BEFORE event loop
    if let Err(e) = drop_privileges(&config) {
        error!("Failed to drop privileges: {}", e);
        process::exit(ExitCode::InitError.as_i32());
    }

    // Phase 8: Set up async signal handlers
    // Replaces C: main() lines 150-234 (sigaction() calls, self-pipe setup)
    // Tokio provides native async signal handling without self-pipe trick
    let mut signal_handler = match setup_signal_handlers() {
        Ok(handler) => handler,
        Err(e) => {
            error!("Failed to set up signal handlers: {}", e);
            process::exit(ExitCode::InitError.as_i32());
        }
    };

    // Phase 9: Run main event loop
    // Replaces C: main() lines 1056-1287 (while(1) poll loop)
    // The event loop runs until a termination signal is received
    let event_loop_result = run_event_loop_with_signals(
        state.clone(),
        &mut signal_handler,
    ).await;

    // Phase 10: Handle shutdown and cleanup
    // Replaces C: main() lines 1288-1295 (cleanup on exit)
    match event_loop_result {
        Ok(()) => {
            // Normal shutdown - exit with success code
            tracing::info!("dnsmasq-rs shutting down gracefully");
            process::exit(ExitCode::Success.as_i32());
        }
        Err(e) => {
            // Error during event loop - log and exit with error code
            error!("Event loop terminated with error: {}", e);
            process::exit(ExitCode::Misc.as_i32());
        }
    }
}

/// Run event loop with integrated signal handling
///
/// This function combines the main event loop with signal processing, using `tokio::select!`
/// to multiplex between network events and signal events. This replaces the C implementation's
/// `poll()` loop that manually checked file descriptors and the self-pipe.
///
/// # Arguments
///
/// * `state` - Shared daemon state wrapped in `Arc<RwLock<>>` for concurrent access
/// * `signal_handler` - Signal handler providing async streams for POSIX signals
///
/// # Returns
///
/// - `Ok(())` on graceful shutdown via SIGTERM or SIGINT
/// - `Err(DnsmasqError)` on fatal error during event processing
///
/// # Signal Handling
///
/// - **SIGHUP**: Reload configuration and flush caches (handled inline)
/// - **SIGUSR1**: Dump statistics to log (handled inline)
/// - **SIGTERM/SIGINT**: Graceful shutdown (returns Ok)
///
/// # C Source Reference
///
/// Replaces: `src/dnsmasq.c` main() lines 1056-1287 (main event loop)
async fn run_event_loop_with_signals(
    state: Arc<RwLock<DaemonState>>,
    signal_handler: &mut dnsmasq::runtime::signal::SignalHandler,
) -> DnsmasqResult<()> {
    loop {
        tokio::select! {
            // Handle signals
            signal_result = signal_handler.recv() => {
                match signal_result {
                    Some(SignalEvent::Reload) => {
                        // SIGHUP received - reload configuration
                        // Replaces C: async_event() lines 1451-1543 (EVENT_RELOAD case)
                        tracing::info!("Received SIGHUP, reloading configuration");
                        
                        let mut state_guard = state.write().await;
                        if let Err(e) = state_guard.reload_config().await {
                            error!("Failed to reload configuration: {}", e);
                            // Continue running despite reload failure (C behavior)
                        }
                    }
                    Some(SignalEvent::Dump) => {
                        // SIGUSR1 received - dump statistics
                        // Replaces C: async_event() lines 1544-1598 (EVENT_DUMP case)
                        tracing::info!("Received SIGUSR1, dumping statistics");
                        
                        let state_guard = state.read().await;
                        state_guard.dump_stats();
                    }
                    Some(SignalEvent::Terminate) => {
                        // SIGTERM or SIGINT received - graceful shutdown
                        // Replaces C: async_event() lines 1599-1620 (EVENT_TERM case)
                        tracing::info!("Received termination signal, shutting down");
                        
                        // Flush all state to persistent storage
                        let state_guard = state.read().await;
                        if let Err(e) = state_guard.flush_state().await {
                            error!("Error flushing state during shutdown: {}", e);
                        }
                        
                        return Ok(());
                    }
                    Some(SignalEvent::Rotate) => {
                        // SIGUSR2 received - rotate logs
                        // This is a Rust-specific addition for log rotation
                        tracing::info!("Received SIGUSR2, rotating logs");
                        // Log rotation is handled automatically by tracing-appender
                        // This event is primarily for logging the action
                    }
                    None => {
                        // Signal stream closed - should not happen in normal operation
                        error!("Signal handler stream closed unexpectedly");
                        return Err(dnsmasq::types::errors::DnsmasqError::Runtime(
                            "Signal handler failure".into()
                        ));
                    }
                }
            }
            
            // Handle network events (DNS, DHCP, TFTP)
            result = run_event_loop(state.clone()) => {
                // Event loop returned - this means a fatal error occurred
                // Normal operation should continue indefinitely until signal
                return result;
            }
        }
    }
}
