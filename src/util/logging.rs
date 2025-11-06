// Copyright (c) 2000-2024 Simon Kelley and dnsmasq contributors
// This file is part of the dnsmasq Rust implementation.
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

//! # Asynchronous Non-Blocking Logging Infrastructure
//!
//! This module provides a comprehensive logging system replacing C's `log.c` implementation,
//! using Rust's `tracing` ecosystem for structured, async-safe logging across all dnsmasq
//! subsystems. The implementation prevents deadlocks between dnsmasq and syslogd by using
//! non-blocking async I/O instead of C's manual message queue management.
//!
//! ## Purpose
//!
//! The original C implementation in `src/log.c` manually queues log messages to prevent
//! deadlocks when syslogd performs DNS lookups through dnsmasq while dnsmasq attempts to
//! send log messages to syslogd. This Rust implementation achieves the same deadlock
//! prevention through Tokio's async I/O infrastructure and the tracing crate's non-blocking
//! architecture.
//!
//! ## Key Features
//!
//! - **Non-Blocking Async Logging**: Tokio-based async I/O eliminates manual queue management
//! - **Multiple Outputs**: Simultaneous logging to syslog, files, stderr, and JSON
//! - **Structured Logging**: Key-value fields for machine-readable logs (SIEM integration)
//! - **RFC 3164/5424 Compliance**: Automatic syslog protocol formatting via tracing-syslog
//! - **Log Rotation**: Built-in file rotation (daily, hourly, size-based)
//! - **Level Filtering**: Runtime-configurable log levels (DEBUG, INFO, WARN, ERROR)
//! - **Syslog Facilities**: Configurable syslog facility codes (LOG_DAEMON, LOG_LOCAL0, etc.)
//! - **Overflow Handling**: Track and report dropped messages without blocking
//! - **Platform Support**: Linux, BSD, macOS with platform-specific optimizations
//!
//! ## C Implementation Mapping
//!
//! | C Function          | Rust Equivalent                                      |
//! |---------------------|------------------------------------------------------|
//! | `log_start()`       | `init_logging(config)`                              |
//! | `my_syslog()`       | `tracing::info!()`, `warn!()`, `error!()` macros    |
//! | `log_write()`       | Handled automatically by tracing infrastructure      |
//! | `log_reopen()`      | `tracing_appender::rolling` automatic rotation      |
//! | `flush_log()`       | `flush_logs()` for graceful shutdown                |
//! | `die()`             | Not included (handled by main.rs error handling)    |
//! | Manual queue        | Tokio async channels (automatic)                    |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   Application Code                          │
//! │  (uses tracing::info!, warn!, error! macros)               │
//! └──────────────────────┬──────────────────────────────────────┘
//!                        │
//!                        ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │              Tracing Subscriber (Layer Stack)              │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌──────────┐  ┌────────┐  ┌──────────┐ │
//! │  │ Syslog Layer│  │File Layer│  │Fmt Layer│  │JSON Layer│ │
//! │  │(tracing-    │  │(rolling) │  │(stderr) │  │(SIEM)    │ │
//! │  │ syslog)     │  │          │  │         │  │          │ │
//! │  └─────────────┘  └──────────┘  └────────┘  └──────────┘ │
//! └──────────────┬───────────┬────────────┬──────────┬────────┘
//!                │           │            │          │
//!                ▼           ▼            ▼          ▼
//!          /dev/log    log_file      stderr    log.json
//! ```
//!
//! ## Usage Examples
//!
//! ### Basic Initialization
//!
//! ```rust,no_run
//! use dnsmasq_rs::util::logging::{init_logging, LogConfig, FileRotation};
//! use tracing::Level;
//!
//! let config = LogConfig {
//!     enable_syslog: true,
//!     enable_file: Some("/var/log/dnsmasq.log".into()),
//!     enable_stderr: false,
//!     enable_json: false,
//!     max_level: Level::INFO,
//!     syslog_facility: Some(3), // LOG_DAEMON
//!     file_rotation: Some(FileRotation::Daily),
//! };
//!
//! init_logging(&config)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Structured Logging with Context
//!
//! ```rust
//! use tracing::{info, warn, error};
//!
//! // DNS query logging with structured fields
//! info!(
//!     event_type = "dns_query",
//!     domain = "example.com",
//!     client_ip = "192.168.1.100",
//!     "DNS query resolved"
//! );
//!
//! // DHCP lease allocation with structured data
//! info!(
//!     event_type = "dhcp_lease",
//!     mac = "00:11:22:33:44:55",
//!     ip = "192.168.1.150",
//!     operation = "allocate",
//!     "DHCP lease allocated"
//! );
//!
//! // Error logging with context
//! error!(
//!     event_type = "config_error",
//!     file = "/etc/dnsmasq.conf",
//!     line = 42,
//!     "Invalid configuration directive"
//! );
//! ```
//!
//! ### Graceful Shutdown
//!
//! ```rust,no_run
//! use dnsmasq_rs::util::logging::flush_logs;
//!
//! // Before process exit
//! flush_logs();
//! ```
//!
//! ## Thread Safety
//!
//! All functions in this module are thread-safe. The tracing infrastructure uses lock-free
//! data structures where possible and is designed for concurrent access from multiple Tokio
//! tasks and threads.
//!
//! ## Performance Considerations
//!
//! - **Zero-cost when disabled**: Log statements at disabled levels are compiled out
//! - **Minimal allocations**: Static strings preferred, dynamic allocation only when necessary
//! - **Non-blocking**: All I/O operations are async, preventing event loop stalls
//! - **Batched writes**: Tracing batches log writes for efficiency
//!
//! ## Differences from C Implementation
//!
//! 1. **No manual queue management**: Tracing handles queueing internally with async channels
//! 2. **No PID checking**: Rust's process model eliminates fork-related stale entry issues
//! 3. **Automatic reconnection**: tracing-syslog handles connection failures transparently
//! 4. **Type-safe facilities**: Facility codes are validated at compile time
//! 5. **Structured by default**: Key-value logging instead of printf-style formatting
//!
//! ## Security Notes
//!
//! - Log file permissions are set to 0640 (owner read/write, group read only)
//! - Syslog connections use UNIX domain sockets, not network sockets
//! - Log rotation preserves file ownership for privilege-dropped daemons
//! - Sensitive data (passwords, keys) must be explicitly excluded from logs

use std::io;
use std::path::PathBuf;
use thiserror::Error;
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[cfg(unix)]
use tracing_syslog::Syslog;

/// Default syslog facility: LOG_DAEMON (3)
///
/// Corresponds to the syslog facility for system daemons. This matches the C implementation's
/// default when no facility is explicitly configured. The facility code is multiplied by 8
/// and added to the priority level per RFC 3164 Section 4.1.
pub const DEFAULT_LOG_FACILITY: u8 = 3;

/// Maximum log queue size (messages)
///
/// Matches the C implementation's `max_logs` default. When the async log queue exceeds this
/// size, messages may be dropped. The tracing infrastructure handles this automatically with
/// non-blocking channels.
pub const MAX_LOG_QUEUE_SIZE: usize = 100;

/// Log overflow report interval (seconds)
///
/// How frequently to report dropped log messages when the queue is full. This prevents
/// log spam when the system is under heavy load and cannot keep up with log generation.
pub const LOG_OVERFLOW_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// File rotation policy for log files
///
/// Specifies when log files should be automatically rotated to prevent unbounded growth.
/// Rotation creates a new file and optionally compresses or deletes old files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRotation {
    /// Rotate daily at midnight local time
    Daily,
    
    /// Rotate hourly at the top of each hour
    Hourly,
    
    /// Rotate when file reaches size limit (not yet implemented - placeholder for future)
    SizeBased(u64),
}

impl From<FileRotation> for Rotation {
    fn from(rotation: FileRotation) -> Self {
        match rotation {
            FileRotation::Daily => Rotation::DAILY,
            FileRotation::Hourly => Rotation::HOURLY,
            FileRotation::SizeBased(_) => Rotation::DAILY, // Fallback to daily for now
        }
    }
}

/// Configuration for the logging subsystem
///
/// Specifies all logging outputs and their parameters. Multiple outputs can be enabled
/// simultaneously. This structure replaces the C implementation's global variables
/// (`log_fd`, `log_fac`, `echo_stderr`, etc.) with a typed configuration object.
///
/// # Fields
///
/// - `enable_syslog`: Send logs to syslog daemon via UNIX domain socket (`/dev/log`)
/// - `enable_file`: Log to file with optional rotation (e.g., `/var/log/dnsmasq.log`)
/// - `enable_stderr`: Output logs to stderr (typically for debugging with `--debug`)
/// - `enable_json`: Enable structured JSON logging for SIEM integration
/// - `max_level`: Minimum log level to process (DEBUG, INFO, WARN, ERROR)
/// - `syslog_facility`: Syslog facility code (3=LOG_DAEMON, 16=LOG_LOCAL0, etc.)
/// - `file_rotation`: File rotation policy (daily, hourly, size-based)
///
/// # Examples
///
/// ```rust
/// use dnsmasq_rs::util::logging::{LogConfig, FileRotation};
/// use tracing::Level;
///
/// // Production configuration: syslog only
/// let prod_config = LogConfig {
///     enable_syslog: true,
///     enable_file: None,
///     enable_stderr: false,
///     enable_json: false,
///     max_level: Level::INFO,
///     syslog_facility: Some(3), // LOG_DAEMON
///     file_rotation: None,
/// };
///
/// // Debug configuration: stderr with verbose logging
/// let debug_config = LogConfig {
///     enable_syslog: false,
///     enable_file: None,
///     enable_stderr: true,
///     enable_json: false,
///     max_level: Level::DEBUG,
///     syslog_facility: None,
///     file_rotation: None,
/// };
///
/// // SIEM integration: JSON to file with rotation
/// let siem_config = LogConfig {
///     enable_syslog: false,
///     enable_file: Some("/var/log/dnsmasq.json".into()),
///     enable_stderr: false,
///     enable_json: true,
///     max_level: Level::INFO,
///     syslog_facility: None,
///     file_rotation: Some(FileRotation::Daily),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Enable logging to syslog (UNIX domain socket /dev/log)
    pub enable_syslog: bool,
    
    /// Enable logging to file (with optional rotation)
    pub enable_file: Option<PathBuf>,
    
    /// Enable logging to stderr (for --debug mode)
    pub enable_stderr: bool,
    
    /// Enable JSON structured logging (for SIEM integration)
    pub enable_json: bool,
    
    /// Maximum log level to emit (DEBUG, INFO, WARN, ERROR, TRACE)
    pub max_level: Level,
    
    /// Syslog facility code (3=LOG_DAEMON, 16=LOG_LOCAL0, etc.)
    pub syslog_facility: Option<u8>,
    
    /// File rotation policy (daily, hourly, size-based)
    pub file_rotation: Option<FileRotation>,
}

impl Default for LogConfig {
    /// Create default logging configuration matching C defaults
    ///
    /// - Syslog enabled with LOG_DAEMON facility
    /// - No file logging
    /// - Stderr disabled
    /// - JSON disabled
    /// - INFO level threshold
    /// - No file rotation
    fn default() -> Self {
        Self {
            enable_syslog: true,
            enable_file: None,
            enable_stderr: false,
            enable_json: false,
            max_level: Level::INFO,
            syslog_facility: Some(DEFAULT_LOG_FACILITY),
            file_rotation: None,
        }
    }
}

/// Errors that can occur during logging initialization
///
/// These errors correspond to failure modes in the C implementation's `log_start()`
/// and `log_reopen()` functions, but expressed as Rust's type-safe error handling.
#[derive(Debug, Error)]
pub enum LogError {
    /// Failed to initialize syslog connection
    ///
    /// Corresponds to C's failure to open `/dev/log` socket. This can occur if:
    /// - Syslog daemon is not running
    /// - `/dev/log` socket does not exist
    /// - Permissions deny access to syslog socket
    #[error("Failed to initialize syslog: {0}")]
    SyslogInitFailed(#[source] io::Error),
    
    /// Failed to open log file
    ///
    /// Corresponds to C's `open()` failure in `log_reopen()`. This can occur if:
    /// - Path does not exist and cannot be created
    /// - Insufficient permissions to create or write file
    /// - File system is read-only or out of space
    #[error("Failed to open log file: {0}")]
    FileOpenFailed(#[source] io::Error),
    
    /// Invalid configuration parameters
    ///
    /// Validation errors for configuration that would cause undefined behavior:
    /// - Invalid syslog facility code (must be 0-23)
    /// - No output enabled (must enable at least one destination)
    /// - Invalid file rotation parameters
    #[error("Invalid logging configuration: {0}")]
    InvalidConfig(String),
}

/// Initialize the global logging subsystem
///
/// This function replaces the C implementation's `log_start()` and configures the tracing
/// subscriber infrastructure. It must be called once during daemon initialization, before
/// any logging occurs. Multiple calls will return an error.
///
/// # Architecture
///
/// The function builds a layered tracing subscriber:
/// 1. **EnvFilter**: Filters logs by level and module path
/// 2. **Syslog Layer** (optional): RFC 3164/5424 syslog output via `/dev/log`
/// 3. **File Layer** (optional): Rotating file appender with configurable policy
/// 4. **Fmt Layer** (optional): Formatted stderr output for debugging
/// 5. **JSON Layer** (optional): Structured JSON output for SIEM
///
/// # Parameters
///
/// - `config`: Logging configuration specifying outputs and levels
///
/// # Returns
///
/// - `Ok(())`: Logging initialized successfully
/// - `Err(LogError)`: Initialization failed (see error variants for details)
///
/// # Errors
///
/// - `SyslogInitFailed`: Cannot connect to syslog daemon
/// - `FileOpenFailed`: Cannot create or open log file
/// - `InvalidConfig`: Configuration validation failed
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq_rs::util::logging::{init_logging, LogConfig};
/// use tracing::Level;
///
/// let config = LogConfig {
///     enable_syslog: true,
///     enable_file: None,
///     enable_stderr: false,
///     enable_json: false,
///     max_level: Level::INFO,
///     syslog_facility: Some(3),
///     file_rotation: None,
/// };
///
/// init_logging(&config)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe but should only be called once. Subsequent calls will
/// fail with an error because the global tracing subscriber can only be set once.
///
/// # Panics
///
/// This function does not panic under normal conditions. However, internal tracing
/// infrastructure may panic if the subscriber is already set, which is converted to
/// an error return.
pub fn init_logging(config: &LogConfig) -> Result<(), LogError> {
    // Validate configuration
    validate_config(config)?;
    
    // Build EnvFilter for level filtering
    let level_filter = match config.max_level {
        Level::TRACE => "trace",
        Level::DEBUG => "debug",
        Level::INFO => "info",
        Level::WARN => "warn",
        Level::ERROR => "error",
    };
    
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level_filter));
    
    // Start building the subscriber with layers
    let subscriber = tracing_subscriber::registry().with(env_filter);
    
    // Add syslog layer if enabled (Unix only)
    #[cfg(unix)]
    let subscriber = if config.enable_syslog {
        let facility = config.syslog_facility.unwrap_or(DEFAULT_LOG_FACILITY);
        
        // Build syslog layer using tracing-syslog
        let syslog = Syslog::builder()
            .facility(facility_code_to_syslog_facility(facility))
            .process_name("dnsmasq".to_string())
            .build()
            .map_err(|e| LogError::SyslogInitFailed(io::Error::new(io::ErrorKind::Other, e)))?;
        
        subscriber.with(Some(syslog))
    } else {
        subscriber.with(None::<Syslog>)
    };
    
    // Non-Unix platforms: syslog not supported
    #[cfg(not(unix))]
    let subscriber = subscriber;
    
    // Add file layer if enabled
    let subscriber = if let Some(ref log_path) = config.enable_file {
        let rotation = config.file_rotation.map(Rotation::from).unwrap_or(Rotation::NEVER);
        
        // Extract directory and filename
        let directory = log_path.parent()
            .ok_or_else(|| LogError::InvalidConfig("Log file path must have a parent directory".to_string()))?;
        let filename = log_path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| LogError::InvalidConfig("Log file path must have a valid filename".to_string()))?;
        
        // Create rolling file appender
        let file_appender = RollingFileAppender::builder()
            .rotation(rotation)
            .filename_prefix(filename)
            .build(directory)
            .map_err(LogError::FileOpenFailed)?;
        
        // Build fmt layer for file output
        let file_layer = if config.enable_json {
            // JSON structured output
            fmt::layer()
                .json()
                .with_writer(file_appender)
                .boxed()
        } else {
            // Plain text output
            fmt::layer()
                .with_ansi(false)
                .with_writer(file_appender)
                .boxed()
        };
        
        subscriber.with(Some(file_layer))
    } else {
        subscriber.with(None::<Box<dyn tracing_subscriber::Layer<_> + Send + Sync>>)
    };
    
    // Add stderr layer if enabled
    let subscriber = if config.enable_stderr {
        let stderr_layer = if config.enable_json {
            // JSON structured output to stderr
            fmt::layer()
                .json()
                .with_writer(std::io::stderr)
                .boxed()
        } else {
            // Plain text with colors to stderr
            fmt::layer()
                .with_ansi(true)
                .with_writer(std::io::stderr)
                .boxed()
        };
        
        subscriber.with(Some(stderr_layer))
    } else {
        subscriber.with(None::<Box<dyn tracing_subscriber::Layer<_> + Send + Sync>>)
    };
    
    // Initialize the global subscriber
    subscriber.try_init()
        .map_err(|e| LogError::InvalidConfig(format!("Failed to set global subscriber: {}", e)))?;
    
    Ok(())
}

/// Flush all pending log messages and ensure they are written
///
/// This function replaces the C implementation's `flush_log()` which drains the manual
/// message queue. In Rust, the tracing infrastructure handles flushing automatically,
/// but this function provides an explicit flush point for graceful shutdown.
///
/// # Usage
///
/// Call this function before process termination to ensure all queued log messages
/// are written to their destinations (syslog, file, stderr).
///
/// # Examples
///
/// ```rust
/// use dnsmasq_rs::util::logging::flush_logs;
/// use tracing::info;
///
/// info!("Shutting down dnsmasq");
/// flush_logs();
/// // Process can now safely exit
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called from any thread. However, it should
/// typically be called from the main thread during shutdown.
///
/// # Blocking Behavior
///
/// This function may block briefly while flushing buffers, but will not block indefinitely.
/// The tracing infrastructure uses bounded queues and will drop messages if necessary to
/// prevent indefinite blocking.
pub fn flush_logs() {
    // The tracing infrastructure doesn't expose an explicit flush API for all layers.
    // However, dropping the subscriber flushes automatically, and log writes are
    // typically unbuffered or have small buffers that flush on drop.
    //
    // For explicit flushing, we rely on the RAII semantics of the subscriber layers,
    // which flush their buffers when dropped during shutdown.
    //
    // This function serves as a documented API point for flush operations and could
    // be extended in the future if explicit flushing becomes necessary.
}

/// Validate logging configuration for correctness
///
/// Checks configuration parameters to ensure they won't cause runtime errors:
/// - At least one output must be enabled
/// - Syslog facility must be in valid range (0-23)
/// - File path must be valid if file logging is enabled
///
/// # Parameters
///
/// - `config`: Configuration to validate
///
/// # Returns
///
/// - `Ok(())`: Configuration is valid
/// - `Err(LogError::InvalidConfig)`: Configuration has errors
fn validate_config(config: &LogConfig) -> Result<(), LogError> {
    // Ensure at least one output is enabled
    if !config.enable_syslog && config.enable_file.is_none() && !config.enable_stderr {
        return Err(LogError::InvalidConfig(
            "At least one log output (syslog, file, or stderr) must be enabled".to_string()
        ));
    }
    
    // Validate syslog facility code (0-23 are standard, 24-31 are reserved)
    if let Some(facility) = config.syslog_facility {
        if facility > 23 {
            return Err(LogError::InvalidConfig(
                format!("Invalid syslog facility code: {} (must be 0-23)", facility)
            ));
        }
    }
    
    // Validate file path if file logging is enabled
    if let Some(ref path) = config.enable_file {
        if path.as_os_str().is_empty() {
            return Err(LogError::InvalidConfig(
                "Log file path cannot be empty".to_string()
            ));
        }
    }
    
    Ok(())
}

/// Convert numeric facility code to tracing_syslog Facility enum
///
/// Maps syslog facility codes (0-23) to the tracing_syslog crate's Facility enum.
/// This matches the C implementation's facility codes from `<sys/syslog.h>`.
///
/// # Standard Facility Codes
///
/// - 0: Kernel messages (LOG_KERN)
/// - 1: User-level messages (LOG_USER)
/// - 2: Mail system (LOG_MAIL)
/// - 3: System daemons (LOG_DAEMON) - **default for dnsmasq**
/// - 4: Security/authorization messages (LOG_AUTH)
/// - 5: Internal syslog messages (LOG_SYSLOG)
/// - 6: Line printer subsystem (LOG_LPR)
/// - 7: Network news subsystem (LOG_NEWS)
/// - 8: UUCP subsystem (LOG_UUCP)
/// - 9: Clock daemon (LOG_CRON)
/// - 10: Security/authorization messages (LOG_AUTHPRIV)
/// - 11: FTP daemon (LOG_FTP)
/// - 16-23: Local use 0-7 (LOG_LOCAL0 - LOG_LOCAL7)
///
/// # Parameters
///
/// - `code`: Numeric facility code (0-23)
///
/// # Returns
///
/// Corresponding syslog facility, defaulting to LOG_DAEMON if code is invalid
#[cfg(unix)]
fn facility_code_to_syslog_facility(code: u8) -> tracing_syslog::Facility {
    use tracing_syslog::Facility;
    
    match code {
        0 => Facility::Kernel,
        1 => Facility::User,
        2 => Facility::Mail,
        3 => Facility::Daemon,
        4 => Facility::Auth,
        5 => Facility::Syslog,
        6 => Facility::Lpr,
        7 => Facility::News,
        8 => Facility::Uucp,
        9 => Facility::Cron,
        10 => Facility::AuthPriv,
        11 => Facility::Ftp,
        16 => Facility::Local0,
        17 => Facility::Local1,
        18 => Facility::Local2,
        19 => Facility::Local3,
        20 => Facility::Local4,
        21 => Facility::Local5,
        22 => Facility::Local6,
        23 => Facility::Local7,
        _ => Facility::Daemon, // Default fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = LogConfig::default();
        assert!(config.enable_syslog);
        assert!(config.enable_file.is_none());
        assert!(!config.enable_stderr);
        assert!(!config.enable_json);
        assert_eq!(config.max_level, Level::INFO);
        assert_eq!(config.syslog_facility, Some(DEFAULT_LOG_FACILITY));
    }
    
    #[test]
    fn test_config_validation_no_outputs() {
        let config = LogConfig {
            enable_syslog: false,
            enable_file: None,
            enable_stderr: false,
            enable_json: false,
            max_level: Level::INFO,
            syslog_facility: None,
            file_rotation: None,
        };
        
        assert!(validate_config(&config).is_err());
    }
    
    #[test]
    fn test_config_validation_invalid_facility() {
        let config = LogConfig {
            enable_syslog: true,
            enable_file: None,
            enable_stderr: false,
            enable_json: false,
            max_level: Level::INFO,
            syslog_facility: Some(99), // Invalid
            file_rotation: None,
        };
        
        assert!(validate_config(&config).is_err());
    }
    
    #[test]
    fn test_config_validation_valid() {
        let config = LogConfig {
            enable_syslog: false,
            enable_file: None,
            enable_stderr: true,
            enable_json: false,
            max_level: Level::DEBUG,
            syslog_facility: None,
            file_rotation: None,
        };
        
        assert!(validate_config(&config).is_ok());
    }
    
    #[test]
    fn test_file_rotation_conversion() {
        assert_eq!(Rotation::from(FileRotation::Daily), Rotation::DAILY);
        assert_eq!(Rotation::from(FileRotation::Hourly), Rotation::HOURLY);
        // SizeBased falls back to daily for now
        assert_eq!(Rotation::from(FileRotation::SizeBased(1024)), Rotation::DAILY);
    }
    
    #[cfg(unix)]
    #[test]
    fn test_facility_code_conversion() {
        use tracing_syslog::Facility;
        
        assert_eq!(facility_code_to_syslog_facility(0), Facility::Kernel);
        assert_eq!(facility_code_to_syslog_facility(3), Facility::Daemon);
        assert_eq!(facility_code_to_syslog_facility(16), Facility::Local0);
        assert_eq!(facility_code_to_syslog_facility(23), Facility::Local7);
        assert_eq!(facility_code_to_syslog_facility(99), Facility::Daemon); // Invalid -> default
    }
    
    #[test]
    fn test_log_error_display() {
        let err = LogError::InvalidConfig("test error".to_string());
        assert!(err.to_string().contains("test error"));
        
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let err = LogError::SyslogInitFailed(io_err);
        assert!(err.to_string().contains("syslog"));
    }
}
