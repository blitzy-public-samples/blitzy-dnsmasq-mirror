// Copyright (c) 2000-2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! Logging subsystem for dnsmasq - async-safe, non-blocking logging with RFC 3164 compliance
//!
//! # Overview
//!
//! This module provides the complete logging infrastructure for the Rust implementation of
//! dnsmasq, replacing C's manual queue management from `src/log.c` with memory-safe,
//! async-capable logging built on the `tracing` crate. The architecture maintains backward
//! compatibility with the C implementation's log message formats while adding modern
//! structured logging capabilities for integration with observability platforms.
//!
//! # Purpose and Design Goals
//!
//! **Primary Objectives:**
//! - **Memory Safety**: Eliminate C's manual malloc/free for log entries by using Rust's
//!   `VecDeque` with automatic memory management via RAII
//! - **Async Non-Blocking I/O**: Prevent deadlocks with syslogd (which may perform DNS
//!   lookups through dnsmasq) by using tokio's async I/O primitives
//! - **Format Compatibility**: Preserve RFC 3164 syslog protocol compliance and maintain
//!   identical log message patterns for operational continuity
//! - **Structured Logging**: Enable machine-parseable JSON output for modern log aggregation
//!   systems (ELK, Splunk, CloudWatch) while retaining plain text option
//! - **Zero Unsafe Code**: Achieve complete type safety without `unsafe` blocks except in
//!   controlled FFI boundaries for syslog socket operations
//!
//! # Architecture
//!
//! The logging subsystem consists of three layers:
//!
//! 1. **Core Logger (`logger` module)**:
//!    - `Logger` struct: Main logging coordinator with message queue management
//!    - `VecDeque<LogEntry>`: Bounded FIFO queue replacing C's manual linked list
//!    - `LogDestination` enum: Abstraction over Syslog, File, and Stderr outputs
//!    - `LogLevel` enum: RFC 3164 priority levels (Emergency through Debug)
//!    - Async write loop: Processes queue with exponential backpressure
//!
//! 2. **Structured Formatters (`structured` module)**:
//!    - `JsonFormatter`: Serializes log events to JSON Lines format with structured fields
//!    - `PlainTextFormatter`: Produces C-compatible output matching original format
//!    - `LogFormat` enum: Runtime format selection via environment variable
//!    - Integration with `tracing_subscriber` for flexible log routing
//!
//! 3. **Public API (this module)**:
//!    - Re-exports all public types and functions for clean module interface
//!    - Hides internal implementation details (queue management, write loops)
//!    - Provides initialization function replacing C's `log_start()`
//!
//! # Memory Safety Improvements over C Implementation
//!
//! | C Pattern (src/log.c) | Rust Replacement | Safety Benefit |
//! |-----------------------|------------------|----------------|
//! | `malloc()`/`free()` for log entries | `VecDeque<LogEntry>` | Automatic deallocation, no leaks |
//! | Manual pointer arithmetic for offsets | Safe slice indexing `&payload[offset..length]` | Bounds checking prevents buffer overruns |
//! | Global mutable state | `Arc<Mutex<VecDeque>>` | Thread-safe shared access |
//! | errno-based error handling | `Result<T, LogError>` | Explicit error propagation |
//! | `strcpy()`/`strcat()` for formatting | `write!()` macro with Vec<u8> | No buffer overflows possible |
//! | Fork detection with `getpid()` | Automatic via `getpid().as_raw()` | Type-safe PID comparison |
//!
//! # RFC 3164 Syslog Protocol Compliance
//!
//! The logger maintains exact compatibility with RFC 3164 (BSD syslog protocol):
//!
//! **Wire Format:**
//! ```text
//! <priority>timestamp hostname tag[pid]: message
//! <14>Jan  1 12:34:56 hostname dnsmasq[12345]: Server started
//! ```
//!
//! **Priority Calculation:**
//! ```text
//! priority = (facility << 3) | severity
//! // Example: LOG_DAEMON (24) with LOG_INFO (6) = (24 << 3) | 6 = 198
//! ```
//!
//! **Timestamp Format:**
//! ```c
//! // C implementation (src/log.c line 770):
//! sprintf(p, "%.15s ", ctime(&time_now) + 4);  // "Jan  1 12:34:56 "
//! ```
//! Rust equivalent uses `chrono` with format `"%b %e %H:%M:%S"` to produce identical output.
//!
//! # Migration from C Implementation
//!
//! **C Functions → Rust Equivalents:**
//!
//! | C Function (src/dnsmasq.h lines 4404-4412) | Rust Function | Notes |
//! |---------------------------------------------|---------------|-------|
//! | `log_start(struct passwd*, int)` | `init_logging()` | Returns `Result<Arc<Logger>>` instead of int |
//! | `log_reopen(char*)` | `Logger::reopen()` | Async method, returns `Result<()>` |
//! | `my_syslog(int, const char*, ...)` | `Logger::log_message()` | Async, type-safe formatting |
//! | `flush_log()` | `Logger::flush_logs()` | Async with automatic cleanup |
//! | `check_log_writer(int)` | (internal) | Integrated into write loop |
//! | `send_event(int, int, int, char*)` | `send_event()` | Compatibility function for init |
//!
//! **Configuration Compatibility:**
//! - `--log-facility=<facility>`: Maps to `init_logging()` facility parameter
//! - `--log-async`: Implicit - all logging is async by default in Rust version
//! - `SIGUSR2`: Triggers `Logger::reopen()` for log file rotation
//!
//! # Usage Examples
//!
//! ## Basic Initialization (Syslog)
//!
//! ```rust,no_run
//! use dnsmasq::logging::{init_logging, LogDestination, LogLevel};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize syslog with LOG_DAEMON facility, INFO level, max 100 queued messages
//!     let logger = init_logging(
//!         LogDestination::Syslog,
//!         None,
//!         LogLevel::Info,
//!         100,
//!         libc::LOG_DAEMON,
//!     ).await?;
//!
//!     // Log a message
//!     logger.log_message(LogLevel::Info, "dns", "Server started").await;
//!
//!     // Flush before shutdown
//!     logger.flush_logs().await;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## File-Based Logging with Rotation
//!
//! ```rust,no_run
//! use dnsmasq::logging::{init_logging, LogDestination, LogLevel};
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let log_path = PathBuf::from("/var/log/dnsmasq.log");
//!     let logger = init_logging(
//!         LogDestination::File(log_path.clone()),
//!         Some(log_path),
//!         LogLevel::Debug,
//!         500,
//!         libc::LOG_DAEMON,
//!     ).await?;
//!
//!     logger.log_message(LogLevel::Debug, "dhcp", "Lease allocated").await;
//!
//!     // Rotate log file (e.g., on SIGUSR2)
//!     logger.reopen().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Structured JSON Logging
//!
//! ```rust,no_run
//! use dnsmasq::logging::{LogFormat, JsonFormatter};
//! use tracing_subscriber::fmt;
//!
//! // Set environment variable to enable JSON formatting
//! std::env::set_var("DNSMASQ_LOG_FORMAT", "json");
//!
//! // Initialize tracing subscriber with JSON formatter
//! fmt()
//!     .event_format(JsonFormatter::new())
//!     .init();
//!
//! // Log with structured fields
//! tracing::info!(
//!     client_ip = "192.168.1.100",
//!     query_type = "A",
//!     domain = "example.com",
//!     response_time_ms = 12,
//!     "DNS query processed"
//! );
//! // Output: {"timestamp":"2024-01-01T12:34:56.789Z","level":"INFO","target":"dnsmasq::dns","message":"DNS query processed","client_ip":"192.168.1.100","query_type":"A","domain":"example.com","response_time_ms":"12"}
//! ```
//!
//! # Module Organization
//!
//! - **`logger`**: Core logging implementation with `Logger` struct, queue management, and I/O
//! - **`structured`**: Format layer with `JsonFormatter` and `PlainTextFormatter` for output
//!
//! # Conditional Compilation
//!
//! Unlike the C implementation which has optional logging via `#ifdef`, logging is always
//! enabled in the Rust version. The minimal overhead of Rust's zero-cost abstractions and
//! the importance of operational visibility justify keeping logging unconditional.
//!
//! # Thread Safety and Async Safety
//!
//! All public types are thread-safe via `Arc` and `Mutex`:
//! - `Logger` can be cloned and shared across tasks
//! - Message queue protected by `tokio::sync::Mutex` for async contexts
//! - No `unsafe` blocks in logging path (except FFI to libc for socket operations)
//!
//! # Performance Characteristics
//!
//! - **Queue overhead**: O(1) push/pop with `VecDeque`
//! - **Memory usage**: Bounded by `max_logs` parameter (default 100 entries × ~1KB = 100KB)
//! - **Async write**: Non-blocking with exponential backpressure after 8 queued entries
//! - **Backpressure delay**: 2^(depth-8) milliseconds, capped at 256ms
//!
//! # Error Handling Philosophy
//!
//! Logging failures are non-fatal by design:
//! - Dropped messages are counted but don't crash the daemon
//! - Connection failures trigger automatic reconnection attempts
//! - Queue full condition drops oldest entries (FIFO eviction)
//! - All errors returned as `Result<(), LogError>` for explicit handling
//!
//! # Integration Points
//!
//! This module is used by:
//! - **Core daemon** (`src_rust/core/daemon.rs`): Initialization and shutdown
//! - **DNS subsystem** (`src_rust/dns/**`): Query logging, cache stats
//! - **DHCP subsystem** (`src_rust/dhcp/**`): Lease allocation, expiry events
//! - **Network layer** (`src_rust/network/**`): Interface changes, socket errors
//! - **Integration modules** (`src_rust/integration/**`): D-Bus events, script execution
//!
//! # Dependencies
//!
//! - **`tracing`**: Core event emission framework
//! - **`tracing-subscriber`**: Format layer and subscriber management
//! - **`tokio`**: Async runtime for non-blocking I/O
//! - **`nix`**: Unix system calls (sockets, getpid)
//! - **`chrono`**: Timestamp formatting for RFC 3164 compliance
//! - **`serde_json`**: JSON serialization for structured logging
//!
//! # Testing Considerations
//!
//! - Unit tests verify log formatting matches C output byte-for-byte
//! - Integration tests validate syslog protocol compliance
//! - Property-based tests ensure queue management correctness under load
//! - Mock implementations available via `LogDestination::Stderr` for testing

// Declare submodules
pub mod logger;
pub mod structured;

// Re-export all public types and functions for clean API
// These match the C API from src/dnsmasq.h lines 4404-4412

// Logger types and core API
pub use logger::{
    init_logging,      // Replaces C's log_start()
    send_event,        // Replaces C's send_event() for init phase
    LogDestination,    // Enum: Syslog | File(PathBuf) | Stderr
    LogError,          // Error type for logging failures
    LogLevel,          // Enum: Emergency..Debug (RFC 3164 priorities)
    Logger,            // Main logger struct with async methods
};

// Structured logging formatters
pub use structured::{
    JsonFormatter,      // JSON Lines formatter for machine parsing
    LogFormat,          // Enum: Json | PlainText (runtime selection)
    PlainTextFormatter, // C-compatible plain text formatter
};

// Convenience re-export for flush_logs at module level
// This provides `dnsmasq::logging::flush_logs()` as an alternative to `logger.flush_logs()`
/// Flush all queued log messages for a given logger
///
/// This is a convenience function that delegates to `Logger::flush_logs()`.
/// Primarily provided for API compatibility with C's `flush_log()` function.
///
/// # Arguments
///
/// * `logger` - Reference to the logger instance to flush
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::logging::{init_logging, flush_logs, LogDestination, LogLevel};
///
/// #[tokio::main]
/// async fn main() {
///     let logger = init_logging(
///         LogDestination::Syslog,
///         None,
///         LogLevel::Info,
///         100,
///         libc::LOG_DAEMON,
///     ).await.unwrap();
///
///     // ... application logic ...
///
///     // Flush logs before shutdown
///     flush_logs(&logger).await;
/// }
/// ```
pub async fn flush_logs(logger: &Logger) {
    logger.flush_logs().await;
}
