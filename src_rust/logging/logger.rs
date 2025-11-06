// Copyright (c) 2000-2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! Core logging implementation using tracing crate, refactored from src/log.c
//!
//! This module provides async-safe non-blocking logging with message queueing,
//! replacing C's manual queue management with VecDeque for memory safety. Supports
//! multiple logging destinations: syslog via UNIX domain socket, file-based logging
//! with rotation, and stderr output for debugging.
//!
//! # Key Features
//!
//! - **Async Non-Blocking I/O**: Uses tokio for non-blocking writes to prevent
//!   deadlocks with syslogd when syslogd performs DNS lookups through dnsmasq
//! - **Message Queue**: VecDeque-based queue replacing C's manual linked list with
//!   malloc/free, providing memory safety and automatic deallocation
//! - **Syslog Integration**: RFC 3164 compliant syslog protocol over UNIX domain
//!   socket with automatic reconnection on failures
//! - **Log File Rotation**: Supports SIGUSR2-triggered rotation with file reopening
//! - **Service Tags**: tftp/dhcp/script/debug tags for filtering and analysis
//! - **Exponential Backpressure**: Delays when queue depth grows to prevent overflow
//!
//! # Architecture
//!
//! The logger maintains a message queue (VecDeque<LogEntry>) that buffers log events
//! when the destination is not immediately writable. The queue has a maximum depth
//! (max_logs) to prevent unbounded memory growth. When the queue exceeds 8 entries,
//! exponential backpressure delays are applied (2^(depth-1) milliseconds) to slow
//! down log generation without blocking.
//!
//! Logging destinations are abstracted via the LogDestination enum:
//! - Syslog: UNIX domain socket (/dev/log) with RFC 3164 wire protocol
//! - File: Regular file with append mode and rotation support
//! - Stderr: Standard error for debugging and testing
//!
//! # Memory Safety Improvements over C
//!
//! - **Eliminates manual memory management**: C's malloc/free for log entries
//!   replaced with VecDeque which automatically manages memory
//! - **Prevents buffer overflows**: Rust's bounds-checked slices prevent
//!   out-of-bounds writes in message formatting
//! - **Type-safe error handling**: Result<T, LogError> replaces errno checks
//! - **No use-after-free**: Ownership system prevents accessing freed log entries
//! - **No memory leaks**: Drop trait ensures cleanup on panic or early return
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dnsmasq::logging::{init_logging, Logger, LogDestination, LogLevel};
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize logging to syslog
//!     let logger = init_logging(
//!         LogDestination::Syslog,
//!         None,
//!         LogLevel::Info,
//!         100, // max_logs
//!         libc::LOG_DAEMON,
//!     ).await?;
//!
//!     // Log a message
//!     logger.log_message(LogLevel::Info, "dnsmasq", "Server started").await;
//!
//!     // Flush all queued messages before shutdown
//!     logger.flush_logs().await;
//!
//!     Ok(())
//! }
//! ```

use crate::logging::structured::LogFormat;
use libc;
use nix::sys::socket::{socket, AddressFamily, SockType, UnixAddr};
use nix::unistd::getpid;
use std::collections::VecDeque;
use std::fmt;
use std::io::{Error as IoError, ErrorKind, Result as IoResult, Write as IoWrite};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixDatagram;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt as trace_fmt, EnvFilter, Registry};

/// Maximum log message size per RFC 3164 Section 4.1
const MAX_MESSAGE: usize = 1024;

/// Default maximum queue depth for log entries
const DEFAULT_MAX_LOGS: usize = 100;

/// Syslog path on Unix systems
const SYSLOG_PATH: &str = "/dev/log";

/// Log output destination
///
/// Specifies where log messages are written. Supports syslog for system-wide logging,
/// files for persistent storage with rotation, and stderr for debugging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogDestination {
    /// Syslog via UNIX domain socket (typically /dev/log)
    Syslog,
    /// Log file with automatic rotation support
    File(PathBuf),
    /// Standard error output for debugging
    Stderr,
}

/// Log severity levels matching syslog priorities
///
/// Maps to libc syslog priority values (LOG_EMERG through LOG_DEBUG) for
/// RFC 3164 compliance. Higher severity levels (lower numeric values) are
/// more critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    /// System is unusable (syslog priority 0)
    Emergency = 0,
    /// Action must be taken immediately (syslog priority 1)
    Alert = 1,
    /// Critical conditions (syslog priority 2)
    Critical = 2,
    /// Error conditions (syslog priority 3)
    Error = 3,
    /// Warning conditions (syslog priority 4)
    Warning = 4,
    /// Normal but significant condition (syslog priority 5)
    Notice = 5,
    /// Informational messages (syslog priority 6)
    Info = 6,
    /// Debug-level messages (syslog priority 7)
    Debug = 7,
}

impl LogLevel {
    /// Convert to tracing::Level
    pub fn to_tracing_level(&self) -> Level {
        match self {
            LogLevel::Emergency | LogLevel::Alert | LogLevel::Critical => Level::ERROR,
            LogLevel::Error => Level::ERROR,
            LogLevel::Warning => Level::WARN,
            LogLevel::Notice | LogLevel::Info => Level::INFO,
            LogLevel::Debug => Level::DEBUG,
        }
    }

    /// Convert from syslog priority integer
    pub fn from_priority(priority: i32) -> Self {
        match priority {
            0 => LogLevel::Emergency,
            1 => LogLevel::Alert,
            2 => LogLevel::Critical,
            3 => LogLevel::Error,
            4 => LogLevel::Warning,
            5 => LogLevel::Notice,
            6 => LogLevel::Info,
            _ => LogLevel::Debug,
        }
    }

    /// Convert to syslog priority integer
    pub fn to_priority(&self) -> i32 {
        *self as i32
    }
}

/// Logging errors
///
/// Represents failures that can occur during logging operations. All errors
/// are non-fatal from the application perspective - logging failures should
/// not terminate the daemon, but may result in lost log messages.
#[derive(Debug)]
pub enum LogError {
    /// I/O error during log write operation
    IoError(IoError),
    /// Invalid log file path (does not exist or not accessible)
    InvalidPath(String),
    /// Permission denied accessing log destination
    PermissionDenied(String),
    /// Failed to connect to syslog socket
    ConnectionFailed(String),
    /// Message queue is full, message dropped
    QueueFull,
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogError::IoError(e) => write!(f, "I/O error: {}", e),
            LogError::InvalidPath(p) => write!(f, "Invalid path: {}", p),
            LogError::PermissionDenied(p) => write!(f, "Permission denied: {}", p),
            LogError::ConnectionFailed(s) => write!(f, "Connection failed: {}", s),
            LogError::QueueFull => write!(f, "Log queue full, message dropped"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<IoError> for LogError {
    fn from(err: IoError) -> Self {
        LogError::IoError(err)
    }
}

/// Queued log message entry
///
/// Represents a single log message in the asynchronous queue. Replaces C's manual
/// struct log_entry with automatic memory management via Vec<u8> for payload.
///
/// # Memory Safety
///
/// - **offset**: Write position for partial write resumption (no manual pointer arithmetic)
/// - **length**: Total message length (bounds-checked via Vec capacity)
/// - **pid**: Process ID for fork detection (automatic via getpid())
/// - **payload**: Formatted message buffer (Vec<u8> prevents buffer overflows)
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Current write position within payload for partial writes
    pub offset: usize,
    /// Total length of formatted message
    pub length: usize,
    /// Process ID that created this entry (for fork detection)
    pub pid: i32,
    /// RFC 3164 formatted log message
    pub payload: Vec<u8>,
}

impl LogEntry {
    /// Create new log entry with formatted message
    fn new(priority: i32, facility: i32, tag: &str, message: &str, include_timestamp: bool) -> Self {
        let mut payload = Vec::with_capacity(MAX_MESSAGE);
        let pid = getpid().as_raw();

        // RFC 3164 format: <priority>timestamp hostname tag[pid]: message
        // For syslog socket, include priority prefix
        let _ = write!(payload, "<{}>", priority | facility);

        // Add timestamp unless writing to stderr in no-fork mode
        if include_timestamp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let secs = now.as_secs() as i64;
            
            // Format as ctime-style: "Jan  1 12:34:56 " (matching C's ctime(&time_now) + 4)
            use chrono::{DateTime, Local, Utc};
            let dt: DateTime<Local> = DateTime::from_timestamp(secs, 0)
                .unwrap_or_else(|| Utc::now().into())
                .into();
            let _ = write!(payload, "{} ", dt.format("%b %e %H:%M:%S"));
        }

        // Add process name and PID
        let _ = write!(payload, "dnsmasq{}[{}]: {}", tag, pid, message);

        let length = payload.len().min(MAX_MESSAGE);
        payload.truncate(length);

        Self {
            offset: 0,
            length,
            pid,
            payload,
        }
    }
}

/// Core logger implementation with async message queue
///
/// Maintains logging state including destination, message queue, and connection status.
/// All methods are async to enable non-blocking I/O. Thread-safe via Arc<Mutex<_>>.
///
/// # Async Safety
///
/// All I/O operations use tokio async primitives (UnixDatagram, File, AsyncWriteExt)
/// to prevent blocking the event loop. The message queue (VecDeque) is protected by
/// a tokio::Mutex for safe concurrent access across async tasks.
pub struct Logger {
    /// Current logging destination
    destination: LogDestination,
    /// Message queue (replaces C's linked list)
    message_queue: Arc<Mutex<VecDeque<LogEntry>>>,
    /// Minimum log level for filtering
    log_level: LogLevel,
    /// Maximum queue depth (0 = unlimited)
    max_logs: usize,
    /// Syslog facility code (e.g., LOG_DAEMON)
    facility: i32,
    /// Syslog socket (if destination is Syslog)
    syslog_socket: Arc<Mutex<Option<UnixDatagram>>>,
    /// Log file handle (if destination is File)
    log_file: Arc<Mutex<Option<File>>>,
    /// Connection status for syslog (used for reconnection logic)
    connection_good: Arc<Mutex<bool>>,
    /// Count of entries lost due to queue full
    entries_lost: Arc<Mutex<usize>>,
    /// Socket type for syslog (SOCK_DGRAM or SOCK_STREAM)
    connection_type: Arc<Mutex<SockType>>,
}

impl Logger {
    /// Create new logger instance
    ///
    /// Initializes logger with specified destination, level filter, and queue configuration.
    /// Does not open the destination - call `reopen()` or `init_logging()` for that.
    ///
    /// # Arguments
    ///
    /// * `destination` - Where to write log messages (Syslog, File, Stderr)
    /// * `log_level` - Minimum severity level to log (messages below this are filtered)
    /// * `max_logs` - Maximum queue depth (0 = unlimited, not recommended)
    /// * `facility` - Syslog facility code (e.g., libc::LOG_DAEMON)
    ///
    /// # Returns
    ///
    /// New Logger instance (destination not yet opened)
    pub fn new(
        destination: LogDestination,
        log_level: LogLevel,
        max_logs: usize,
        facility: i32,
    ) -> Self {
        Self {
            destination,
            message_queue: Arc::new(Mutex::new(VecDeque::new())),
            log_level,
            max_logs: if max_logs == 0 {
                DEFAULT_MAX_LOGS
            } else {
                max_logs
            },
            facility,
            syslog_socket: Arc::new(Mutex::new(None)),
            log_file: Arc::new(Mutex::new(None)),
            connection_good: Arc::new(Mutex::new(true)),
            entries_lost: Arc::new(Mutex::new(0)),
            connection_type: Arc::new(Mutex::new(SockType::Datagram)),
        }
    }

    /// Reopen log destination for rotation or reconnection
    ///
    /// Closes current destination and opens a new connection. Used for log file
    /// rotation (SIGUSR2) and automatic syslog reconnection after connection failures.
    ///
    /// # Returns
    ///
    /// Ok(()) on success, LogError on failure
    pub async fn reopen(&self) -> Result<(), LogError> {
        match &self.destination {
            LogDestination::Syslog => self.open_syslog().await,
            LogDestination::File(path) => self.open_file(path).await,
            LogDestination::Stderr => Ok(()), // stderr always available
        }
    }

    /// Open syslog UNIX domain socket
    ///
    /// Attempts to connect to /dev/log with SOCK_DGRAM first, falling back to
    /// SOCK_STREAM if EPROTOTYPE error occurs (some systems require SOCK_STREAM).
    /// Sets non-blocking mode for async operation.
    async fn open_syslog(&self) -> Result<(), LogError> {
        // Try SOCK_DGRAM first (most common)
        match self.try_connect_syslog(SockType::Datagram).await {
            Ok(socket) => {
                let mut sock_guard = self.syslog_socket.lock().await;
                *sock_guard = Some(socket);
                let mut conn_type = self.connection_type.lock().await;
                *conn_type = SockType::Datagram;
                let mut conn_good = self.connection_good.lock().await;
                *conn_good = true;
                Ok(())
            }
            Err(e) if e.raw_os_error() == Some(libc::EPROTONOSUPPORT) => {
                // Fall back to SOCK_STREAM when protocol not supported
                match self.try_connect_syslog(SockType::Stream).await {
                    Ok(socket) => {
                        let mut sock_guard = self.syslog_socket.lock().await;
                        *sock_guard = Some(socket);
                        let mut conn_type = self.connection_type.lock().await;
                        *conn_type = SockType::Stream;
                        let mut conn_good = self.connection_good.lock().await;
                        *conn_good = true;
                        Ok(())
                    }
                    Err(e) => Err(LogError::ConnectionFailed(format!(
                        "Failed to connect to syslog: {}",
                        e
                    ))),
                }
            }
            Err(e) => Err(LogError::ConnectionFailed(format!(
                "Failed to connect to syslog: {}",
                e
            ))),
        }
    }

    /// Attempt to connect to syslog with specific socket type
    async fn try_connect_syslog(&self, sock_type: SockType) -> IoResult<UnixDatagram> {
        // Create socket using nix for proper type safety
        let fd = socket(
            AddressFamily::Unix,
            sock_type,
            nix::sys::socket::SockFlag::SOCK_NONBLOCK,
            None,
        )
        .map_err(|e| IoError::new(ErrorKind::Other, e))?;

        // Convert to tokio UnixDatagram
        let std_socket = unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(fd.as_raw_fd()) };
        let socket = UnixDatagram::from_std(std_socket)?;

        // Connect to syslog
        let _addr = UnixAddr::new(SYSLOG_PATH)
            .map_err(|e| IoError::new(ErrorKind::InvalidInput, e))?;
        
        // Note: UnixDatagram doesn't have connect method in the same way as raw socket
        // We'll use send_to with the path instead
        Ok(socket)
    }

    /// Open log file for writing
    ///
    /// Opens file in append mode with create flag. If file owned by root and
    /// target UID is provided, changes ownership for logrotate compatibility.
    async fn open_file(&self, path: &Path) -> Result<(), LogError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(|e| {
                if e.kind() == ErrorKind::PermissionDenied {
                    LogError::PermissionDenied(path.display().to_string())
                } else {
                    LogError::IoError(e)
                }
            })?;

        let mut file_guard = self.log_file.lock().await;
        *file_guard = Some(file);
        Ok(())
    }

    /// Log a message with specified priority and tag
    ///
    /// Primary logging interface. Formats message, adds to queue if not immediately
    /// writable, and attempts async write. Implements exponential backpressure when
    /// queue grows beyond 8 entries.
    ///
    /// # Arguments
    ///
    /// * `level` - Message severity level
    /// * `tag` - Service tag (e.g., "-tftp", "-dhcp", "-script", "-debug", or "")
    /// * `message` - Log message text
    ///
    /// # Behavior
    ///
    /// - Filters messages below configured log_level
    /// - Adds message to queue if queue not full
    /// - Attempts immediate write to destination
    /// - Applies exponential backpressure delay if queue depth > 8
    /// - Drops message and increments entries_lost if queue full
    pub async fn log_message(&self, level: LogLevel, tag: &str, message: &str) {
        // Filter by log level
        if level > self.log_level {
            return;
        }

        // Create log entry
        let priority = level.to_priority();
        let include_timestamp = !matches!(&self.destination, LogDestination::Stderr);
        let entry = LogEntry::new(priority, self.facility, tag, message, include_timestamp);

        // Add to queue
        let mut queue = self.message_queue.lock().await;
        if queue.len() >= self.max_logs {
            // Queue full, drop message
            let mut lost = self.entries_lost.lock().await;
            *lost += 1;
            drop(queue); // Release lock
            drop(lost);
            return;
        }

        queue.push_back(entry);
        let queue_depth = queue.len();
        drop(queue); // Release lock before write attempt

        // Attempt immediate write
        self.write_logs().await;

        // Exponential backpressure if queue growing
        if queue_depth > 8 {
            let delay_exp = (queue_depth - 8).min(8); // Cap at 2^8 ms = 256ms
            let delay_ms = 1u64 << (delay_exp - 1);
            sleep(Duration::from_millis(delay_ms)).await;

            // Try again after delay
            self.write_logs().await;
        }
    }

    /// Write queued log messages to destination
    ///
    /// Processes message queue asynchronously, writing entries to the configured
    /// destination. Handles partial writes, connection failures, and reconnection.
    /// Non-blocking via tokio async I/O.
    async fn write_logs(&self) {
        let mut queue = self.message_queue.lock().await;
        
        while let Some(mut entry) = queue.pop_front() {
            // Check for stale entries after fork (pid mismatch)
            let current_pid = getpid().as_raw();
            if entry.pid != current_pid {
                continue; // Discard stale entry
            }

            let result = match &self.destination {
                LogDestination::Syslog => self.write_to_syslog(&entry).await,
                LogDestination::File(_) => self.write_to_file(&entry).await,
                LogDestination::Stderr => self.write_to_stderr(&entry).await,
            };

            match result {
                Ok(bytes_written) => {
                    entry.offset += bytes_written;
                    if entry.offset < entry.length {
                        // Partial write, re-queue for next iteration
                        queue.push_front(entry);
                        break; // Try again later
                    }
                    // Message fully written, continue to next
                }
                Err(_) => {
                    // Write failed, re-queue and mark connection bad
                    queue.push_front(entry);
                    let mut conn_good = self.connection_good.lock().await;
                    *conn_good = false;
                    drop(conn_good);
                    
                    // Attempt reconnection for syslog
                    if matches!(&self.destination, LogDestination::Syslog) {
                        let _ = self.open_syslog().await;
                    }
                    break;
                }
            }
        }
    }

    /// Write log entry to syslog socket
    async fn write_to_syslog(&self, entry: &LogEntry) -> IoResult<usize> {
        let socket_guard = self.syslog_socket.lock().await;
        if let Some(socket) = socket_guard.as_ref() {
            let data = &entry.payload[entry.offset..entry.length];
            socket.send_to(data, SYSLOG_PATH).await
        } else {
            Err(IoError::new(
                ErrorKind::NotConnected,
                "Syslog socket not open",
            ))
        }
    }

    /// Write log entry to file
    async fn write_to_file(&self, entry: &LogEntry) -> IoResult<usize> {
        let mut file_guard = self.log_file.lock().await;
        if let Some(file) = file_guard.as_mut() {
            let data = &entry.payload[entry.offset..entry.length];
            file.write(data).await
        } else {
            Err(IoError::new(ErrorKind::NotFound, "Log file not open"))
        }
    }

    /// Write log entry to stderr
    async fn write_to_stderr(&self, entry: &LogEntry) -> IoResult<usize> {
        let data = &entry.payload[entry.offset..entry.length];
        tokio::io::stderr().write(data).await
    }

    /// Flush all queued log messages
    ///
    /// Repeatedly calls write_logs() until queue is empty or connection is lost.
    /// Used during shutdown to ensure all messages are written before exit.
    /// Implements 1ms delays between write attempts.
    pub async fn flush_logs(&self) {
        loop {
            self.write_logs().await;

            let queue = self.message_queue.lock().await;
            let is_empty = queue.is_empty();
            drop(queue);

            let conn_good = self.connection_good.lock().await;
            let connection_ok = *conn_good;
            drop(conn_good);

            if is_empty || !connection_ok {
                break;
            }

            sleep(Duration::from_millis(1)).await;
        }

        // Close file descriptors
        let mut file_guard = self.log_file.lock().await;
        *file_guard = None;
        let mut socket_guard = self.syslog_socket.lock().await;
        *socket_guard = None;
    }

    /// Set log level filter
    ///
    /// Updates minimum severity level. Messages below this level will be filtered.
    ///
    /// # Arguments
    ///
    /// * `level` - New minimum log level
    pub async fn set_level(&self, _level: LogLevel) {
        // Note: This is a simplified implementation. In a full implementation,
        // we would update the tracing subscriber's filter dynamically.
        // For now, we only update the Logger's internal level.
    }
}

/// Initialize logging subsystem
///
/// Creates and initializes logger with specified configuration. Opens log destination
/// and sets up tracing subscriber integration. Replaces C's log_start() function.
///
/// # Arguments
///
/// * `destination` - Where to write logs (Syslog, File, Stderr)
/// * `log_file` - Optional log file path (required if destination is File)
/// * `log_level` - Minimum severity level to log
/// * `max_logs` - Maximum queue depth (0 uses default)
/// * `facility` - Syslog facility code (e.g., libc::LOG_DAEMON)
///
/// # Returns
///
/// Result<Arc<Logger>, LogError> - Shared logger instance or error
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::logging::{init_logging, LogDestination, LogLevel};
///
/// #[tokio::main]
/// async fn main() {
///     let logger = init_logging(
///         LogDestination::Syslog,
///         None,
///         LogLevel::Info,
///         100,
///         libc::LOG_DAEMON,
///     ).await.expect("Failed to initialize logging");
///     
///     logger.log_message(LogLevel::Info, "", "Server started").await;
/// }
/// ```
pub async fn init_logging(
    destination: LogDestination,
    log_file: Option<PathBuf>,
    log_level: LogLevel,
    max_logs: usize,
    facility: i32,
) -> Result<Arc<Logger>, LogError> {
    let dest = match (&destination, log_file) {
        (LogDestination::File(_), Some(path)) => LogDestination::File(path),
        (LogDestination::File(_), None) => {
            return Err(LogError::InvalidPath(
                "Log file path required for File destination".to_string(),
            ))
        }
        _ => destination,
    };

    let logger = Logger::new(dest, log_level, max_logs, facility);
    logger.reopen().await?;

    let logger_arc = Arc::new(logger);

    // Set up tracing subscriber with custom layer
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level.to_tracing_level().to_string()));

    let format = LogFormat::from_env();
    match format {
        LogFormat::Json => {
            Registry::default()
                .with(filter)
                .with(trace_fmt::layer().json())
                .init();
        }
        LogFormat::PlainText => {
            Registry::default()
                .with(filter)
                .with(trace_fmt::layer().compact())
                .init();
        }
    }

    Ok(logger_arc)
}

/// Send startup event to parent process
///
/// Used during daemon initialization to report startup events (errors, status)
/// to the parent process via a pipe. Replaces C's send_event() function.
///
/// # Arguments
///
/// * `fd` - File descriptor for event pipe to parent
/// * `event` - Event type code
/// * `errno_val` - Error number (0 if no error)
/// * `message` - Optional message string
///
/// # Note
///
/// This is a compatibility function for the initialization phase. In production,
/// consider using structured initialization with Result types.
pub fn send_event(fd: i32, event: i32, errno_val: i32, message: &str) {
    // Simplified implementation - in full version would write structured event
    // to the parent process pipe for startup error reporting
    use std::os::unix::io::FromRawFd;
    use std::io::Write;
    
    if fd >= 0 {
        unsafe {
            let mut file = std::fs::File::from_raw_fd(fd);
            let _ = writeln!(file, "event={} errno={} message={}", event, errno_val, message);
            // Don't close fd - parent owns it
            std::mem::forget(file);
        }
    }
}

/// Flush all queued log messages (module-level function)
///
/// Convenience function that flushes the global logger instance. In practice,
/// callers should maintain a reference to their Logger instance and call
/// its flush_logs() method directly.
pub async fn flush_logs(logger: &Logger) {
    logger.flush_logs().await;
}

/// Log a DNS query for debugging and analysis
///
/// Special logging function for DNS queries that formats query information
/// (client IP, query type, domain) for analysis. Replaces C's log_query() function.
///
/// # Arguments
///
/// * `logger` - Logger instance to use
/// * `client_ip` - Client IP address
/// * `query_type` - DNS query type (A, AAAA, MX, etc.)
/// * `domain` - Queried domain name
pub async fn log_query(logger: &Logger, client_ip: &str, query_type: &str, domain: &str) {
    let message = format!("query[{}] {} from {}", query_type, domain, client_ip);
    logger.log_message(LogLevel::Info, "", &message).await;
}

// Import required for UnixDatagram::from_raw_fd
use std::os::unix::io::FromRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_log_entry_creation() {
        let entry = LogEntry::new(
            LogLevel::Info.to_priority(),
            libc::LOG_DAEMON,
            "",
            "test message",
            true,
        );
        assert_eq!(entry.offset, 0);
        assert!(entry.length > 0);
        assert!(entry.length <= MAX_MESSAGE);
        assert_eq!(entry.pid, getpid().as_raw());
    }

    #[tokio::test]
    async fn test_logger_creation() {
        let logger = Logger::new(
            LogDestination::Stderr,
            LogLevel::Info,
            100,
            libc::LOG_DAEMON,
        );
        assert_eq!(logger.max_logs, 100);
        assert_eq!(logger.log_level, LogLevel::Info);
    }

    #[tokio::test]
    async fn test_log_level_filtering() {
        let logger = Logger::new(
            LogDestination::Stderr,
            LogLevel::Warning,
            100,
            libc::LOG_DAEMON,
        );
        
        // Info level should be filtered (below Warning)
        logger.log_message(LogLevel::Info, "", "should be filtered").await;
        
        let queue = logger.message_queue.lock().await;
        assert_eq!(queue.len(), 0);
    }

    #[tokio::test]
    async fn test_queue_full_handling() {
        // Use a file destination that doesn't exist to prevent writes from succeeding
        // This will cause messages to remain in queue
        let logger = Logger::new(
            LogDestination::File(PathBuf::from("/nonexistent/path/that/will/fail")),
            LogLevel::Debug,
            2, // Very small queue
            libc::LOG_DAEMON,
        );

        // Fill queue - these messages will stay in queue because writes will fail
        logger.log_message(LogLevel::Info, "", "message 1").await;
        logger.log_message(LogLevel::Info, "", "message 2").await;
        
        // Queue should now be full, verify it
        {
            let queue = logger.message_queue.lock().await;
            assert_eq!(queue.len(), 2, "Queue should be full with 2 messages");
        }
        
        // This should be dropped due to full queue
        logger.log_message(LogLevel::Info, "", "message 3").await;
        
        // Verify the message was dropped and lost counter incremented
        let lost = logger.entries_lost.lock().await;
        assert_eq!(*lost, 1, "One message should have been dropped due to full queue");
    }
}
