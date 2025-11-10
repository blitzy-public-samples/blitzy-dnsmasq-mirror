//! Core Runtime and Event Loop Subsystem
//!
//! This module provides the foundational runtime infrastructure for the dnsmasq Rust
//! implementation, replacing C's global state management and poll()-based event loop
//! with memory-safe, async-first architecture.
//!
//! # Architecture Overview
//!
//! The core subsystem consists of four primary components:
//!
//! ## 1. Daemon State Management (`daemon`)
//!
//! The [`Daemon`] struct replaces C's global `daemon` pointer with a thread-safe,
//! reference-counted state container using `Arc<RwLock<Daemon>>`. This eliminates
//! memory safety issues inherent in C's shared mutable global state while enabling
//! concurrent access across async tasks.
//!
//! **C Equivalent:**
//! ```c
//! // src/dnsmasq.h
//! extern struct daemon *daemon;  // Global mutable state
//! ```
//!
//! **Rust Replacement:**
//! ```rust
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use dnsmasq::core::Daemon;
//!
//! let daemon = Arc::new(RwLock::new(Daemon::new(config)?));
//! ```
//!
//! ## 2. Compile-Time Configuration (`config`)
//!
//! Compile-time constants and feature gates from C's `config.h` are translated into
//! Rust const items and conditional compilation attributes. This preserves the ability
//! to tune performance characteristics at compile time while leveraging Rust's type
//! system for additional safety.
//!
//! **C Equivalent:**
//! ```c
//! // src/config.h
//! #define CACHESIZ 150
//! #define FTABSIZ 150
//! ```
//!
//! ## 3. Signal Handling (`signals`)
//!
//! The [`SignalHandler`] replaces C's unsafe POSIX signal handlers and self-pipe pattern
//! with Tokio's async signal streams. All signal events (SIGHUP, SIGUSR1, SIGUSR2,
//! SIGTERM, SIGINT, SIGCHLD) are delivered through a memory-safe MPSC channel.
//!
//! **C Equivalent:**
//! ```c
//! // src/dnsmasq.c
//! static void sig_handler(int sig) {
//!     write(pipefd[1], &sig, 1);  // Self-pipe pattern
//! }
//! ```
//!
//! **Rust Replacement:**
//! ```rust
//! use dnsmasq::core::SignalHandler;
//!
//! let mut signal_handler = SignalHandler::new()?;
//! while let Some(event) = signal_handler.recv().await {
//!     // Process signal event safely
//! }
//! ```
//!
//! ## 4. Event Loop (`event_loop`)
//!
//! The [`run_event_loop`] function replaces C's poll()-based synchronous event loop
//! with a modern async event loop using `tokio::select!`. This enables concurrent
//! processing of DNS queries, DHCP requests, TFTP transfers, and control events
//! without blocking or manual multiplexing.
//!
//! **C Equivalent:**
//! ```c
//! // src/dnsmasq.c, src/poll.c
//! void event_loop(void) {
//!     while (1) {
//!         poll(fds, nfds, timeout);
//!         // Process ready file descriptors
//!     }
//! }
//! ```
//!
//! **Rust Replacement:**
//! ```rust
//! use dnsmasq::core::run_event_loop;
//!
//! run_event_loop(daemon, config, logger).await?;
//! ```
//!
//! # Module Dependencies and Initialization Order
//!
//! The core subsystem has the following dependency structure:
//!
//! ```text
//! core
//! ├── config          (compile-time constants)
//! ├── daemon          (runtime state container)
//! │   └── → config
//! ├── signals         (async signal handling)
//! │   └── → (no dependencies)
//! └── event_loop      (main event loop)
//!     ├── → daemon
//!     ├── → config
//!     └── → signals
//! ```
//!
//! **Initialization Order:**
//! 1. Parse configuration (`config::Config::from_args()`)
//! 2. Create daemon instance (`Daemon::new(config)`)
//! 3. Initialize logging (`Logger::init()`)
//! 4. Run event loop (`run_event_loop(daemon, config, logger)`)
//!
//! # Memory Safety Guarantees
//!
//! The core subsystem eliminates several classes of memory safety vulnerabilities
//! present in the C implementation:
//!
//! - **No Global Mutable State**: All state is encapsulated in `Daemon` with
//!   explicit ownership and borrowing rules enforced by the compiler
//! - **No Manual Memory Management**: RAII via `Drop` trait eliminates memory leaks,
//!   double-frees, and use-after-free bugs
//! - **Thread-Safe Concurrency**: `Arc`, `Mutex`, and `RwLock` provide race-free
//!   shared state access across async tasks
//! - **Type-Safe Signal Handling**: Signal events are strongly typed enums rather
//!   than raw integer constants, preventing invalid signal codes
//!
//! # Performance Characteristics
//!
//! The async architecture provides several performance advantages:
//!
//! - **Zero-Copy Networking**: Tokio's async I/O minimizes buffer copies
//! - **Task Concurrency**: Multiple DNS queries can be processed concurrently
//!   without thread overhead
//! - **Efficient Multiplexing**: `tokio::select!` replaces manual poll() management
//! - **Cache-Friendly**: `Arc` enables sharing without copying large structures
//!
//! # Public API
//!
//! The following items are re-exported for use by other subsystems:
//!
//! - [`Daemon`]: Main daemon state container
//! - [`SignalHandler`]: Async signal event receiver
//! - [`run_event_loop`]: Event loop entry point
//!
//! # Internal APIs
//!
//! The following modules are public but contain implementation details:
//!
//! - `config`: Compile-time configuration (constants only)
//! - `daemon`: Full `Daemon` implementation
//! - `signals`: Signal handling implementation
//! - `event_loop`: Event loop implementation
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```rust,ignore
//! use dnsmasq::core::{Daemon, run_event_loop};
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Parse configuration
//!     let config = Config::from_args()?;
//!     let config = Arc::new(config);
//!     
//!     // 2. Create daemon
//!     let daemon = Arc::new(RwLock::new(Daemon::new(config.clone())?));
//!     
//!     // 3. Initialize logging
//!     let logger = Arc::new(Logger::init(&config)?);
//!     
//!     // 4. Run event loop (blocks until shutdown)
//!     run_event_loop(daemon, config, logger).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Accessing Daemon State
//!
//! ```rust,ignore
//! use dnsmasq::core::Daemon;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! async fn query_cache(daemon: Arc<RwLock<Daemon>>, query: &str) {
//!     // Read-only access to cache (multiple concurrent readers allowed)
//!     let daemon_read = daemon.read().await;
//!     let cache = daemon_read.get_cache();
//!     
//!     if let Some(entry) = cache.lock().await.lookup(query) {
//!         println!("Cache hit: {:?}", entry);
//!     }
//! }
//! ```
//!
//! # C Implementation References
//!
//! This module replaces functionality from the following C files:
//!
//! - `src/dnsmasq.h`: Global type definitions and daemon struct
//! - `src/dnsmasq.c`: Main entry point, signal handling, event loop
//! - `src/config.h`: Compile-time configuration constants
//! - `src/poll.c`: Poll-based event multiplexing
//!
//! # See Also
//!
//! - [`dns`](crate::dns): DNS subsystem
//! - [`dhcp`](crate::dhcp): DHCP subsystem
//! - [`network`](crate::network): Network layer

// ============================================================================
// Module Declarations
// ============================================================================

/// Compile-time configuration constants
///
/// Replaces C's `config.h` with type-safe Rust const items and feature gates.
/// Contains tuning parameters like cache sizes, table limits, and timeout values.
pub mod config;

/// Daemon state container and builder
///
/// Provides the main `Daemon` struct that encapsulates all runtime state,
/// replacing C's global `daemon` pointer with thread-safe shared ownership.
pub mod daemon;

/// Async signal handling
///
/// Replaces POSIX signal handlers and self-pipe pattern with Tokio async
/// signal streams and MPSC channels for memory-safe signal delivery.
pub mod signals;

/// Main async event loop
///
/// Replaces poll()-based event multiplexing with `tokio::select!` for
/// concurrent processing of network events, timers, and signals.
pub mod event_loop;

// ============================================================================
// Public API Re-exports
// ============================================================================

// Re-export primary public types for convenient access
pub use daemon::Daemon;
pub use signals::SignalHandler;
pub use event_loop::run_event_loop;
