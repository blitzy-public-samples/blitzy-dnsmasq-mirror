// dnsmasq-rs - Rust implementation of dnsmasq
// Copyright (C) 2024 dnsmasq-rs contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) version 3 of the License.

//! Signal handling for daemon lifecycle management
//!
//! This module replaces C's self-pipe pattern for async-signal-safe operation
//! (sig_handler() function in dnsmasq.c lines 1536-1583) with Tokio's signal
//! handlers, providing safe async signal delivery without manual pipe management.
//!
//! # C Implementation Background
//!
//! The original C implementation uses the self-pipe trick where signal handlers
//! write event codes to a pipe, which the main event loop polls. This pattern
//! ensures async-signal-safety by only calling write(2) in signal context.
//!
//! # Rust Implementation
//!
//! Tokio's signal infrastructure handles async-signal-safety internally, allowing
//! us to eliminate manual pipe management. Signal streams are multiplexed using
//! tokio::select! into a single event channel consumed by the main event loop.
//!
//! # Signal Mapping
//!
//! The following signals are handled, matching dnsmasq.c behavior:
//!
//! - **SIGHUP (1)** → `SignalEvent::Reload` - Reload configuration without restart
//! - **SIGUSR1 (10)** → `SignalEvent::DumpCache` - Dump DNS cache statistics
//! - **SIGUSR2 (12)** → `SignalEvent::ReopenLog` - Reopen log files for rotation
//! - **SIGTERM (15)** → `SignalEvent::Terminate` - Graceful shutdown with lease flush
//! - **SIGINT (2)** → `SignalEvent::TimeCheck` or immediate exit in debug mode
//! - **SIGCHLD (17)** → `SignalEvent::ChildExited` - Helper process terminated
//! - **SIGALRM (14)** → `SignalEvent::TimerExpired` - Timer expiration (replaced by tokio::time)
//!
//! # Example Usage
//!
//! ```no_run
//! use dnsmasq::runtime::signal::{setup_signal_handlers, SignalEvent};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut signal_handler = setup_signal_handlers()?;
//!     
//!     loop {
//!         tokio::select! {
//!             Some(event) = signal_handler.recv() => {
//!                 match event {
//!                     SignalEvent::Reload => {
//!                         // Reload configuration
//!                     }
//!                     SignalEvent::Terminate => {
//!                         // Graceful shutdown
//!                         break;
//!                     }
//!                     _ => {
//!                         // Handle other signals
//!                     }
//!                 }
//!             }
//!         }
//!     }
//!     
//!     Ok(())
//! }
//! ```

use std::process;
use thiserror::Error;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, Sleep, interval, sleep_until};
use tracing::info;

/// Signal events that can occur during daemon operation
///
/// These events correspond to C's EVENT_* constants defined in dnsmasq.h:
/// - EVENT_RELOAD (1) → Reload
/// - EVENT_DUMP (2) → DumpCache
/// - EVENT_REOPEN (6) → ReopenLog
/// - EVENT_TERM (4) → Terminate
/// - EVENT_TIME (26) → TimeCheck
/// - EVENT_CHILD (5) → ChildExited
/// - EVENT_ALARM (3) → TimerExpired
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalEvent {
    /// SIGTERM received - initiate graceful shutdown with DHCP lease flush
    ///
    /// Corresponds to C's EVENT_TERM. The daemon should:
    /// 1. Stop accepting new requests
    /// 2. Flush DHCP lease database to disk
    /// 3. Close all sockets gracefully
    /// 4. Exit with status code 0
    Terminate,

    /// SIGHUP received - reload configuration without restarting
    ///
    /// Corresponds to C's EVENT_RELOAD. The daemon should:
    /// 1. Re-parse configuration files (dnsmasq.conf, /etc/hosts, /etc/resolv.conf)
    /// 2. Flush DNS cache
    /// 3. Re-read DHCP host declarations
    /// 4. Apply new upstream DNS servers
    /// 5. Continue operation with new configuration
    Reload,

    /// SIGUSR1 received - dump DNS cache statistics to logs
    ///
    /// Corresponds to C's EVENT_DUMP. The daemon should log:
    /// - Cache size and utilization
    /// - Cache hit/miss ratios
    /// - Currently cached entries
    /// - Upstream server statistics
    DumpCache,

    /// SIGUSR2 received - reopen log files for log rotation
    ///
    /// Corresponds to C's EVENT_REOPEN. The daemon should:
    /// 1. Close current log file handles
    /// 2. Reopen log files (allows logrotate to work)
    /// 3. Continue logging to new file
    ReopenLog,

    /// SIGINT received in non-debug mode - trigger DNSSEC time check
    ///
    /// Corresponds to C's EVENT_TIME. Used to:
    /// - Check if system time has progressed sufficiently for DNSSEC validation
    /// - Re-validate DNSSEC signatures after time sync
    ///
    /// Note: In debug mode (cfg!(debug_assertions)), SIGINT causes immediate exit
    TimeCheck,

    /// SIGCHLD received - child process (DHCP helper script) exited
    ///
    /// Corresponds to C's EVENT_CHILD. The daemon should:
    /// 1. Reap zombie processes using waitpid() or tokio::process::Child::wait()
    /// 2. Check exit status of DHCP lease-change scripts
    /// 3. Log any script failures
    ChildExited,

    /// Timer expired (replaces C's SIGALRM-based timers)
    ///
    /// Corresponds to C's EVENT_ALARM. Used for:
    /// - DHCP lease expiration checks
    /// - DNS query timeouts
    /// - Periodic maintenance tasks
    ///
    /// In Rust, timers are handled via tokio::time rather than SIGALRM,
    /// but this event maintains API compatibility
    TimerExpired,
}

/// Signal handler errors
///
/// Comprehensive error types for signal setup and runtime failures
#[derive(Error, Debug)]
pub enum SignalError {
    /// Failed to set up signal handler for a specific signal
    ///
    /// This can occur if:
    /// - Signal is already handled by another handler (SIG_IGN, SIG_DFL overridden)
    /// - System resources exhausted (file descriptors)
    /// - Platform doesn't support the signal
    #[error("Signal setup failed for {signal}: {source}")]
    SignalSetupFailed {
        /// Name of the signal (e.g., "SIGHUP", "SIGTERM")
        signal: String,
        /// Underlying I/O error from signal registration
        source: std::io::Error,
    },

    /// Signal stream closed unexpectedly
    ///
    /// Indicates the signal multiplexer task has terminated, which should not
    /// happen during normal daemon operation. This is a fatal error.
    #[error("Signal stream closed unexpectedly - signal handler task terminated")]
    SignalStreamClosed,

    /// Invalid signal encountered
    ///
    /// Used for future extensibility if custom signal handling is added
    #[error("Invalid signal: {0}")]
    InvalidSignal(String),

    /// Timer-related error
    ///
    /// Errors from tokio::time operations (sleep, interval scheduling)
    #[error("Timer error: {0}")]
    TimerError(String),

    /// I/O error during signal operations
    ///
    /// Generic I/O errors from underlying system calls
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Signal handler that multiplexes POSIX signals into async events
///
/// This struct wraps a tokio::sync::mpsc::Receiver that delivers SignalEvents
/// from the signal multiplexer task. It provides a clean async API for
/// receiving signals in the main event loop.
///
/// # Lifecycle
///
/// 1. Created by `setup_signal_handlers()`
/// 2. Consumed by main event loop via `recv()` calls
/// 3. Closed explicitly via `close()` or automatically on drop
///
/// # Concurrency
///
/// Safe to use across await points but not Send across threads (contains !Send Receiver)
pub struct SignalHandler {
    /// Channel receiver for signal events
    receiver: mpsc::Receiver<SignalEvent>,
}

impl SignalHandler {
    /// Receive the next signal event asynchronously
    ///
    /// Returns `Some(SignalEvent)` when a signal is received, or `None` if the
    /// signal handler is shutting down (channel closed).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::runtime::signal::{setup_signal_handlers, SignalEvent};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut handler = setup_signal_handlers()?;
    ///
    /// while let Some(event) = handler.recv().await {
    ///     match event {
    ///         SignalEvent::Terminate => break,
    ///         SignalEvent::Reload => { /* reload config */ }
    ///         _ => { /* handle other events */ }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn recv(&mut self) -> Option<SignalEvent> {
        self.receiver.recv().await
    }

    /// Close the signal handler, preventing further signal reception
    ///
    /// After calling this method, `recv()` will return `None` immediately.
    /// This is useful for graceful shutdown when you want to stop processing
    /// signals but continue other async operations.
    pub fn close(&mut self) {
        self.receiver.close();
    }
}

/// Set up signal handlers for all daemon lifecycle signals
///
/// Creates Tokio signal streams for POSIX signals (SIGHUP, SIGUSR1, SIGUSR2,
/// SIGTERM, SIGINT, SIGCHLD, SIGALRM) and spawns a background task that
/// multiplexes them into a single event stream.
///
/// This replaces C's sig_handler() function and self-pipe pattern with Tokio's
/// safe async signal infrastructure.
///
/// # Returns
///
/// - `Ok(SignalHandler)` - Signal handler ready to receive events
/// - `Err(SignalError)` - Signal setup failed (see error for details)
///
/// # Errors
///
/// Returns `SignalError::SignalSetupFailed` if any signal cannot be registered.
/// Common causes:
/// - Signal already has a custom handler installed
/// - System resource exhaustion
/// - Platform doesn't support the signal (e.g., SIGALRM on some systems)
///
/// # Platform Compatibility
///
/// This function is Unix-specific and will not compile on Windows. For Windows
/// support, use tokio::signal::windows::ctrl_c() and ctrl_break().
///
/// # Example
///
/// ```no_run
/// use dnsmasq::runtime::signal::setup_signal_handlers;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut signals = setup_signal_handlers()?;
///     println!("Signal handlers installed successfully");
///     Ok(())
/// }
/// ```
#[cfg(unix)]
pub fn setup_signal_handlers() -> Result<SignalHandler, SignalError> {
    info!("Setting up POSIX signal handlers for daemon lifecycle management");

    // Create signal streams for each POSIX signal we handle
    // These streams are async-safe internally - Tokio handles the complexity

    let mut sighup = signal(SignalKind::hangup()).map_err(|e| SignalError::SignalSetupFailed {
        signal: "SIGHUP".to_string(),
        source: e,
    })?;
    info!("Registered SIGHUP (1) handler for configuration reload");

    let mut sigusr1 =
        signal(SignalKind::user_defined1()).map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGUSR1".to_string(),
            source: e,
        })?;
    info!("Registered SIGUSR1 (10) handler for cache dump");

    let mut sigusr2 =
        signal(SignalKind::user_defined2()).map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGUSR2".to_string(),
            source: e,
        })?;
    info!("Registered SIGUSR2 (12) handler for log rotation");

    let mut sigterm =
        signal(SignalKind::terminate()).map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGTERM".to_string(),
            source: e,
        })?;
    info!("Registered SIGTERM (15) handler for graceful shutdown");

    let mut sigint =
        signal(SignalKind::interrupt()).map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGINT".to_string(),
            source: e,
        })?;
    info!("Registered SIGINT (2) handler for debug exit or DNSSEC time check");

    let mut sigchld = signal(SignalKind::child()).map_err(|e| SignalError::SignalSetupFailed {
        signal: "SIGCHLD".to_string(),
        source: e,
    })?;
    info!("Registered SIGCHLD (17) handler for helper process reaping");

    let mut sigalrm = signal(SignalKind::alarm()).map_err(|e| SignalError::SignalSetupFailed {
        signal: "SIGALRM".to_string(),
        source: e,
    })?;
    info!("Registered SIGALRM (14) handler for timer expiry (legacy compatibility)");

    // Create bounded channel for signal events
    // Buffer size of 32 allows burst of signals without blocking signal task
    let (sender, receiver) = mpsc::channel(32);

    // Spawn background task to multiplex all signals into single event stream
    // This task runs for the lifetime of the daemon
    tokio::spawn(async move {
        info!("Signal multiplexer task started");

        loop {
            // Use tokio::select! to wait on all signal streams concurrently
            // First signal to arrive gets processed
            tokio::select! {
                Some(_) = sighup.recv() => {
                    info!("SIGHUP received - triggering configuration reload");
                    if sender.send(SignalEvent::Reload).await.is_err() {
                        info!("Signal receiver dropped - shutting down signal handler");
                        break;
                    }
                }

                Some(_) = sigusr1.recv() => {
                    info!("SIGUSR1 received - triggering DNS cache dump");
                    if sender.send(SignalEvent::DumpCache).await.is_err() {
                        info!("Signal receiver dropped - shutting down signal handler");
                        break;
                    }
                }

                Some(_) = sigusr2.recv() => {
                    info!("SIGUSR2 received - triggering log file reopen");
                    if sender.send(SignalEvent::ReopenLog).await.is_err() {
                        info!("Signal receiver dropped - shutting down signal handler");
                        break;
                    }
                }

                Some(_) = sigterm.recv() => {
                    info!("SIGTERM received - triggering graceful shutdown");
                    if sender.send(SignalEvent::Terminate).await.is_err() {
                        info!("Signal receiver dropped - shutting down signal handler");
                        break;
                    }
                }

                Some(_) = sigint.recv() => {
                    // Debug mode: exit immediately on SIGINT (Ctrl-C)
                    // This matches C behavior in dnsmasq.c lines 1572-1573
                    if cfg!(debug_assertions) {
                        info!("SIGINT received in debug mode - exiting immediately");
                        process::exit(1);
                    } else {
                        info!("SIGINT received - triggering DNSSEC time validation check");
                        if sender.send(SignalEvent::TimeCheck).await.is_err() {
                            info!("Signal receiver dropped - shutting down signal handler");
                            break;
                        }
                    }
                }

                Some(_) = sigchld.recv() => {
                    info!("SIGCHLD received - child process terminated");
                    if sender.send(SignalEvent::ChildExited).await.is_err() {
                        info!("Signal receiver dropped - shutting down signal handler");
                        break;
                    }
                }

                Some(_) = sigalrm.recv() => {
                    info!("SIGALRM received - timer expired (legacy alarm support)");
                    if sender.send(SignalEvent::TimerExpired).await.is_err() {
                        info!("Signal receiver dropped - shutting down signal handler");
                        break;
                    }
                }
            }
        }

        info!("Signal multiplexer task terminated");
    });

    info!("Signal handlers configured successfully - daemon ready for lifecycle events");

    Ok(SignalHandler { receiver })
}

/// Schedule a timer that fires after the specified duration
///
/// This function provides a clean API for scheduling one-shot timers that
/// deliver `SignalEvent::TimerExpired` when they expire. It replaces C's
/// send_alarm() function which used alarm(2) and SIGALRM.
///
/// # Arguments
///
/// * `duration` - Time to wait before timer expires
///
/// # Returns
///
/// Future that resolves to `SignalEvent::TimerExpired` after the duration
///
/// # Example
///
/// ```no_run
/// use dnsmasq::runtime::signal::{schedule_timer, SignalEvent};
/// use tokio::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///     let event = schedule_timer(Duration::from_secs(5)).await;
///     assert_eq!(event, SignalEvent::TimerExpired);
///     println!("Timer expired after 5 seconds");
/// }
/// ```
pub async fn schedule_timer(duration: Duration) -> SignalEvent {
    let deadline = Instant::now() + duration;
    sleep_until(deadline).await;
    SignalEvent::TimerExpired
}

/// Create a periodic interval timer that triggers repeatedly
///
/// This function creates a `tokio::time::Interval` that can be polled
/// repeatedly to receive periodic timer events. It replaces C's pattern
/// of repeatedly calling alarm() for periodic tasks.
///
/// # Arguments
///
/// * `period` - Time between timer ticks
///
/// # Returns
///
/// Interval that can be polled for periodic events
///
/// # Example
///
/// ```no_run
/// use dnsmasq::runtime::signal::create_interval_timer;
/// use tokio::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///     let mut timer = create_interval_timer(Duration::from_secs(60));
///     
///     loop {
///         timer.tick().await;
///         println!("Periodic maintenance task");
///     }
/// }
/// ```
pub fn create_interval_timer(period: Duration) -> tokio::time::Interval {
    interval(period)
}

/// Create a `Sleep` future that can be cancelled
///
/// Returns a tokio::time::Sleep future that completes after the specified
/// duration. Unlike `schedule_timer`, this allows the caller to cancel the
/// timer by dropping the returned future.
///
/// # Arguments
///
/// * `duration` - Time to wait before timer expires
///
/// # Returns
///
/// Sleep future that resolves after the duration
///
/// # Example
///
/// ```no_run
/// use dnsmasq::runtime::signal::create_cancellable_timer;
/// use tokio::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///     let sleep = create_cancellable_timer(Duration::from_secs(10));
///     
///     tokio::select! {
///         _ = sleep => println!("Timer expired"),
///         _ = tokio::signal::ctrl_c() => println!("Cancelled by Ctrl-C"),
///     }
/// }
/// ```
pub fn create_cancellable_timer(duration: Duration) -> Sleep {
    let deadline = Instant::now() + duration;
    tokio::time::sleep_until(deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[test]
    fn test_signal_event_equality() {
        assert_eq!(SignalEvent::Terminate, SignalEvent::Terminate);
        assert_ne!(SignalEvent::Terminate, SignalEvent::Reload);
        assert_eq!(SignalEvent::DumpCache, SignalEvent::DumpCache);
    }

    #[test]
    fn test_signal_event_debug() {
        let event = SignalEvent::Reload;
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("Reload"));
    }

    #[test]
    fn test_signal_event_copy() {
        let event1 = SignalEvent::TimeCheck;
        let event2 = event1; // Copy
        assert_eq!(event1, event2);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_signal_handler_setup() {
        let result = setup_signal_handlers();
        assert!(
            result.is_ok(),
            "Signal handler setup should succeed on Unix platforms"
        );
    }

    #[tokio::test]
    async fn test_schedule_timer() {
        let start = Instant::now();
        let duration = Duration::from_millis(50);

        let event = schedule_timer(duration).await;

        assert_eq!(event, SignalEvent::TimerExpired);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= duration,
            "Timer should wait at least {:?}, but only waited {:?}",
            duration,
            elapsed
        );
        assert!(
            elapsed < duration + Duration::from_millis(100),
            "Timer should not significantly overshoot"
        );
    }

    #[tokio::test]
    async fn test_create_interval_timer() {
        let mut timer = create_interval_timer(Duration::from_millis(25));

        let start = Instant::now();

        // First tick is immediate
        timer.tick().await;

        // Second tick should wait ~25ms
        timer.tick().await;
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(25),
            "Interval should wait at least 25ms"
        );
    }

    #[tokio::test]
    async fn test_cancellable_timer() {
        let sleep = create_cancellable_timer(Duration::from_millis(100));

        tokio::select! {
            _ = sleep => {
                // Timer completed normally
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                panic!("Cancellable timer should complete before fallback");
            }
        }
    }

    #[tokio::test]
    async fn test_cancellable_timer_cancellation() {
        let sleep = create_cancellable_timer(Duration::from_secs(10));
        let cancel_signal = tokio::time::sleep(Duration::from_millis(50));

        let cancelled = tokio::select! {
            _ = sleep => false,
            _ = cancel_signal => true,
        };

        assert!(cancelled, "Timer should be cancelled by early signal");
    }

    #[test]
    fn test_signal_error_display() {
        let error = SignalError::InvalidSignal("SIGUSR3".to_string());
        let display = format!("{}", error);
        assert!(display.contains("Invalid signal"));
        assert!(display.contains("SIGUSR3"));
    }

    #[test]
    fn test_signal_error_stream_closed() {
        let error = SignalError::SignalStreamClosed;
        let display = format!("{}", error);
        assert!(display.contains("Signal stream closed"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_signal_handler_close() {
        let mut handler = setup_signal_handlers().expect("Signal setup should succeed");

        // Close the handler
        handler.close();

        // recv() should immediately return None
        let result = handler.recv().await;
        assert_eq!(
            result, None,
            "Closed signal handler should return None immediately"
        );
    }
}
