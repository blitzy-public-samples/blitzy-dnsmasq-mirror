//! Signal handling for daemon lifecycle management
//!
//! This module replaces C's self-pipe pattern for async-signal-safe operation
//! with Tokio's signal handlers, providing safe async signal delivery.

use thiserror::Error;
use tokio::signal::unix::{signal, Signal, SignalKind};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant, Duration, interval};
use tracing::{info, warn, error};

/// Signal events that can occur during daemon operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalEvent {
    /// SIGTERM/SIGINT - Graceful shutdown with lease flush
    Terminate,
    
    /// SIGHUP - Reload configuration without restart
    Reload,
    
    /// SIGUSR1 - Dump DNS cache to logs
    DumpCache,
    
    /// SIGUSR2 - Reopen log files for rotation
    ReopenLog,
    
    /// SIGINT - DNSSEC time check (non-debug mode)
    TimeCheck,
    
    /// SIGCHLD - Helper process termination
    ChildExited,
    
    /// SIGALRM - Timer expiry
    TimerExpired,
}

/// Signal handler errors
#[derive(Error, Debug)]
pub enum SignalError {
    /// Failed to set up signal handler
    #[error("Signal setup failed for {signal}: {source}")]
    SignalSetupFailed {
        signal: String,
        source: std::io::Error,
    },
    
    /// Signal stream closed unexpectedly
    #[error("Signal stream closed")]
    SignalStreamClosed,
    
    /// Invalid signal
    #[error("Invalid signal: {0}")]
    InvalidSignal(String),
    
    /// Timer error
    #[error("Timer error: {0}")]
    TimerError(String),
    
    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Signal handler that multiplexes POSIX signals into events
pub struct SignalHandler {
    receiver: mpsc::Receiver<SignalEvent>,
}

impl SignalHandler {
    /// Receive the next signal event
    ///
    /// Returns None if signal handler is shutting down
    pub async fn recv(&mut self) -> Option<SignalEvent> {
        self.receiver.recv().await
    }
    
    /// Close the signal handler
    pub fn close(&mut self) {
        self.receiver.close();
    }
}

/// Set up signal handlers for all daemon signals
///
/// Creates Tokio signal streams for POSIX signals and multiplexes them
/// into a single event stream for the main event loop.
///
/// # Returns
///
/// SignalHandler that provides signal events
pub fn setup_signal_handlers() -> Result<SignalHandler, SignalError> {
    info!("Setting up signal handlers");
    
    // Create signal streams for each signal
    let mut sighup = signal(SignalKind::hangup())
        .map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGHUP".to_string(),
            source: e,
        })?;
    
    let mut sigusr1 = signal(SignalKind::user_defined1())
        .map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGUSR1".to_string(),
            source: e,
        })?;
    
    let mut sigusr2 = signal(SignalKind::user_defined2())
        .map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGUSR2".to_string(),
            source: e,
        })?;
    
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGTERM".to_string(),
            source: e,
        })?;
    
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGINT".to_string(),
            source: e,
        })?;
    
    let mut sigchld = signal(SignalKind::child())
        .map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGCHLD".to_string(),
            source: e,
        })?;
    
    let mut sigalrm = signal(SignalKind::alarm())
        .map_err(|e| SignalError::SignalSetupFailed {
            signal: "SIGALRM".to_string(),
            source: e,
        })?;
    
    // Create channel for signal events
    let (sender, receiver) = mpsc::channel(32);
    
    // Spawn task to multiplex signals
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sighup.recv() => {
                    info!("Received SIGHUP - config reload");
                    if sender.send(SignalEvent::Reload).await.is_err() {
                        break;
                    }
                }
                _ = sigusr1.recv() => {
                    info!("Received SIGUSR1 - cache dump");
                    if sender.send(SignalEvent::DumpCache).await.is_err() {
                        break;
                    }
                }
                _ = sigusr2.recv() => {
                    info!("Received SIGUSR2 - log reopen");
                    if sender.send(SignalEvent::ReopenLog).await.is_err() {
                        break;
                    }
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM - graceful shutdown");
                    if sender.send(SignalEvent::Terminate).await.is_err() {
                        break;
                    }
                }
                _ = sigint.recv() => {
                    // In debug mode, exit immediately
                    if cfg!(debug_assertions) {
                        warn!("Received SIGINT in debug mode - exiting");
                        std::process::exit(1);
                    } else {
                        info!("Received SIGINT - time check");
                        if sender.send(SignalEvent::TimeCheck).await.is_err() {
                            break;
                        }
                    }
                }
                _ = sigchld.recv() => {
                    info!("Received SIGCHLD - child exited");
                    if sender.send(SignalEvent::ChildExited).await.is_err() {
                        break;
                    }
                }
                _ = sigalrm.recv() => {
                    info!("Received SIGALRM - timer expired");
                    if sender.send(SignalEvent::TimerExpired).await.is_err() {
                        break;
                    }
                }
            }
        }
        
        info!("Signal handler task shutting down");
    });
    
    info!("Signal handlers set up successfully");
    
    Ok(SignalHandler { receiver })
}

/// Schedule a timer that fires after the specified duration
///
/// Returns a future that completes when the timer expires
pub async fn schedule_timer(duration: Duration) -> SignalEvent {
    sleep_until(Instant::now() + duration).await;
    SignalEvent::TimerExpired
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signal_event_equality() {
        assert_eq!(SignalEvent::Terminate, SignalEvent::Terminate);
        assert_ne!(SignalEvent::Terminate, SignalEvent::Reload);
    }
    
    #[tokio::test]
    async fn test_signal_handler_setup() {
        let result = setup_signal_handlers();
        assert!(result.is_ok(), "Signal handler setup should succeed");
    }
    
    #[tokio::test]
    async fn test_schedule_timer() {
        let start = Instant::now();
        let duration = Duration::from_millis(100);
        
        let event = schedule_timer(duration).await;
        
        assert_eq!(event, SignalEvent::TimerExpired);
        assert!(start.elapsed() >= duration);
    }
}
