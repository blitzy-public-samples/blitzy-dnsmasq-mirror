//! Signal handling
//!
//! Handle Unix signals (SIGHUP, SIGUSR1, SIGTERM, etc.)
//! 
//! This module provides async signal handling using tokio's signal primitives.
//! Signals are converted into typed events that can be processed by the main event loop.

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

/// Signal event types corresponding to Unix signals
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalEvent {
    /// SIGHUP - Reload configuration
    Reload,
    /// SIGTERM - Terminate daemon gracefully
    Terminate,
    /// SIGINT - Interrupt (Ctrl+C)
    Interrupt,
    /// SIGUSR1 - Dump statistics/debug info
    DumpStats,
    /// SIGUSR2 - Reopen log files
    ReopenLogs,
}

/// Setup signal handlers and return a channel to receive signal events
/// 
/// This function registers signal handlers for SIGHUP, SIGTERM, SIGINT, SIGUSR1, and SIGUSR2.
/// When a signal is received, the corresponding SignalEvent is sent through the returned channel.
/// 
/// # Returns
/// 
/// Returns a receiver channel that yields SignalEvent values when signals are received.
/// 
/// # Errors
/// 
/// Returns an error if signal handler registration fails (typically due to system resource limits).
/// 
/// # Example
/// 
/// ```no_run
/// use dnsmasq::core::signals;
/// 
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut signal_rx = signals::setup_signal_handlers().await?;
///     
///     loop {
///         if let Some(event) = signal_rx.recv().await {
///             match event {
///                 signals::SignalEvent::Reload => {
///                     // Reload configuration
///                 }
///                 signals::SignalEvent::Terminate => {
///                     // Graceful shutdown
///                     break;
///                 }
///                 signals::SignalEvent::Interrupt => {
///                     // Handle Ctrl+C
///                     break;
///                 }
///                 signals::SignalEvent::DumpStats => {
///                     // Dump statistics
///                 }
///                 signals::SignalEvent::ReopenLogs => {
///                     // Reopen log files
///                 }
///             }
///         }
///     }
///     Ok(())
/// }
/// ```
pub async fn setup_signal_handlers() -> Result<mpsc::UnboundedReceiver<SignalEvent>, std::io::Error> {
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigusr2 = signal(SignalKind::user_defined2())?;
    
    let (tx, rx) = mpsc::unbounded_channel();
    
    // Spawn task to handle SIGHUP (reload configuration)
    let tx_hup = tx.clone();
    tokio::spawn(async move {
        loop {
            sighup.recv().await;
            if tx_hup.send(SignalEvent::Reload).is_err() {
                break; // Channel closed, exit task
            }
        }
    });
    
    // Spawn task to handle SIGTERM (graceful termination)
    let tx_term = tx.clone();
    tokio::spawn(async move {
        loop {
            sigterm.recv().await;
            if tx_term.send(SignalEvent::Terminate).is_err() {
                break;
            }
        }
    });
    
    // Spawn task to handle SIGINT (Ctrl+C interrupt)
    let tx_int = tx.clone();
    tokio::spawn(async move {
        loop {
            sigint.recv().await;
            if tx_int.send(SignalEvent::Interrupt).is_err() {
                break;
            }
        }
    });
    
    // Spawn task to handle SIGUSR1 (dump statistics)
    let tx_usr1 = tx.clone();
    tokio::spawn(async move {
        loop {
            sigusr1.recv().await;
            if tx_usr1.send(SignalEvent::DumpStats).is_err() {
                break;
            }
        }
    });
    
    // Spawn task to handle SIGUSR2 (reopen log files)
    tokio::spawn(async move {
        loop {
            sigusr2.recv().await;
            if tx.send(SignalEvent::ReopenLogs).is_err() {
                break;
            }
        }
    });
    
    Ok(rx)
}
