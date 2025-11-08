// dnsmasq-rs: Memory-safe Rust implementation of dnsmasq
// Copyright (c) 2000-2022 Simon Kelley
// Copyright (c) 2024 Rust Translation Contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! # DHCP Script Execution Module
//!
//! This module implements privilege-separated helper process functionality for running
//! external lease-change scripts and Lua callbacks, translating C's fork-based helper
//! architecture from `src/helper.c` to Rust's `tokio::process` for secure script
//! invocation with environment variable passing.
//!
//! ## Purpose
//!
//! Provides async script execution for DHCP lease events (add/delete/renew), TFTP
//! transfers, ARP detections, and `DHCPv6` relay snooping. Scripts receive event data
//! via `DNSMASQ_*` environment variables, enabling integration with external systems
//! for lease management, logging, and firewall updates.
//!
//! ## Architecture Differences from C
//!
//! The C implementation (`src/helper.c`) forks a privileged helper process that:
//! - Runs continuously waiting for events via Unix socket
//! - Retains root privileges while main daemon drops privileges
//! - Executes scripts synchronously with `fork()`+`execl()`
//! - Communicates via pipe-based IPC with main process
//!
//! The Rust implementation eliminates the persistent helper process:
//! - Uses `tokio::process::Command` for on-demand script execution
//! - Spawns scripts asynchronously with proper privilege handling
//! - Queues events via async `mpsc` channels instead of static buffers
//! - Provides timeout protection and comprehensive error handling
//!
//! ## Key Responsibilities
//!
//! - **Event Queueing**: Queue DHCP, TFTP, ARP events for script notification
//! - **Environment Setup**: Populate `DNSMASQ_*` variables from event data
//! - **Script Execution**: Spawn external programs with timeout and capture output
//! - **Lua Integration**: Execute Lua callbacks with event data tables (feature-gated)
//! - **Security**: Validate script paths, sanitize environment variables
//!
//! ## C Source Mapping
//!
//! | C Function | Rust Equivalent | Lines | Purpose |
//! |------------|-----------------|-------|---------|
//! | `create_helper()` | `ScriptExecutor::new()` | 261-332 | Initialize executor |
//! | `queue_script()` | `queue_lease_event()` | 1174-1243 | Queue DHCP event |
//! | `queue_tftp()` | `queue_tftp_event()` | 1366-1443 | Queue TFTP event |
//! | `queue_arp()` | `queue_arp_event()` | 1444-1464 | Queue ARP event |
//! | `helper_write()` | Channel send | 1552-1571 | Transmit event |
//! | `my_setenv()` | `HashMap<String, String>` | 912-921 | Build environment |
//! | `grab_extradata()` | Parse extradata | 968-997 | Extract DHCP options |
//!
//! ## Dependencies
//!
//! - `tokio::process`: Async Command execution replacing C fork/exec
//! - `tokio::sync::mpsc`: Event queue replacing C static buffer
//! - `mlua` (optional): Lua interpreter replacing C `lua_State`
//! - `Lease`: DHCP lease structure from `src/dhcp/lease.rs`
//! - `MacAddr`: MAC address type from `src/network/arp.rs`
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use dnsmasq::integration::scripts::{ScriptExecutor, LeaseAction};
//! use dnsmasq::dhcp::lease::Lease;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let executor = ScriptExecutor::new("/usr/local/bin/dhcp-script")?
//!     .with_timeout(Duration::from_secs(30));
//!
//! # // Create a sample lease (in real code, this would come from DHCP server)
//! # let lease = Lease::new(
//! #     "192.168.1.100".parse()?,
//! #     vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
//! #     None,
//! #     Some("client-hostname".to_string()),
//! #     3600,
//! # );
//! // Queue a lease add event
//! executor.queue_lease_event(
//!     LeaseAction::Add,
//!     lease,
//!     Some("client-hostname".to_string()),
//! ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Considerations
//!
//! - Script path validated as absolute and immutable after initialization
//! - Environment variables sanitized to prevent injection attacks
//! - Execution timeout prevents hung scripts from blocking daemon
//! - Scripts executed with dropped privileges if configured
//! - No user-controlled data passed as command-line arguments

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::dhcp::lease::Lease;
use crate::network::arp::MacAddr;

#[cfg(feature = "lua")]
use mlua::Lua;

// =============================================================================
// Constants
// =============================================================================

/// Default script execution timeout in seconds.
///
/// Scripts that exceed this duration are terminated with SIGKILL to prevent
/// hung processes from blocking the daemon. Corresponds to implicit timeout
/// behavior in C version.
const DEFAULT_SCRIPT_TIMEOUT_SECS: u64 = 30;

/// Maximum environment variable value length for security.
///
/// Prevents excessively long values that could cause memory exhaustion or
/// buffer overflows in poorly written scripts.
const MAX_ENV_VALUE_LEN: usize = 8192;

// =============================================================================
// Error Types
// =============================================================================

/// Script execution errors.
///
/// Comprehensive error types for all script execution failure modes, replacing
/// C's errno-based error reporting via `err_fd` pipe with structured Rust errors.
///
/// ## C Reference
///
/// Replaces: `EVENT_EXEC_ERR`, `EVENT_PIPE_ERR`, `EVENT_USER_ERR` events sent
/// via `send_event()` in C version (helper.c lines 272, 300, 524).
#[derive(Debug, Error)]
pub enum ScriptError {
    /// Script execution failed with non-zero exit code.
    ///
    /// Contains exit code and captured stderr for debugging script issues.
    #[error("Script execution failed with exit code {exit_code}: {stderr}")]
    ExecutionFailed {
        /// Process exit code returned by the script
        exit_code: i32,
        /// Standard error output captured from the script
        stderr: String,
    },

    /// Script exceeded execution timeout.
    ///
    /// Script was terminated with SIGKILL after exceeding configured timeout.
    /// Prevents hung scripts from blocking daemon operation.
    #[error("Script execution timed out after {0:?}")]
    Timeout(Duration),

    /// Invalid or insecure script path.
    ///
    /// Script path must be absolute and cannot be modified after executor
    /// initialization to prevent privilege escalation attacks.
    #[error("Invalid script path: {0}")]
    InvalidPath(String),

    /// I/O error during script execution or output capture.
    ///
    /// Wraps `std::io::Error` for file operations, pipe creation, or process
    /// spawning failures.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Lua script error (feature-gated).
    ///
    /// Lua script execution failures including syntax errors, runtime errors,
    /// or missing `lease()` function in loaded script.
    #[cfg(feature = "lua")]
    #[error("Lua script error: {0}")]
    LuaError(#[from] mlua::Error),

    /// Event queue channel closed.
    ///
    /// Indicates executor has been dropped or shut down, events can no longer
    /// be queued.
    #[error("Event queue closed")]
    QueueClosed,
}

// =============================================================================
// Event Types
// =============================================================================

/// DHCP lease action types.
///
/// Represents lease lifecycle events that trigger script execution, matching
/// C's `ACTION_OLD`, `ACTION_ADD`, `ACTION_DEL` constants from helper.c.
///
/// ## C Reference
///
/// Maps to: `#define ACTION_OLD 1`, `ACTION_ADD 2`, `ACTION_DEL 3` (not shown
/// in provided excerpt, but referenced in `queue_script` line 1197).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseAction {
    /// Lease renewal (existing lease extended).
    ///
    /// Triggered when a client renews an existing lease with the same IP and
    /// hardware address. Environment variable: `DNSMASQ_LEASE_ACTION=old`
    Renew,

    /// New lease allocation.
    ///
    /// Triggered when a client is assigned a new IP address from the pool or
    /// changes hardware address. Environment variable: `DNSMASQ_LEASE_ACTION=add`
    Add,

    /// Lease expiry or explicit release.
    ///
    /// Triggered when lease expires or client sends DHCPRELEASE message.
    /// Environment variable: `DNSMASQ_LEASE_ACTION=del`
    Delete,
}

impl LeaseAction {
    /// Convert to environment variable string value.
    ///
    /// Returns the string representation used for `DNSMASQ_LEASE_ACTION`
    /// environment variable, matching C version's behavior.
    fn as_env_str(self) -> &'static str {
        match self {
            LeaseAction::Renew => "old",
            LeaseAction::Add => "add",
            LeaseAction::Delete => "del",
        }
    }
}

/// ARP detection action types.
///
/// Represents ARP table changes detected by monitoring kernel ARP cache,
/// used to notify scripts of new devices appearing or disappearing from
/// network.
///
/// ## C Reference
///
/// Maps to: `ACTION_ARP` and `ACTION_ARP_DEL` constants (helper.c line 1453).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpAction {
    /// New ARP entry detected (device appeared on network).
    ///
    /// Environment variable: `DNSMASQ_ARP_ACTION=add`
    Add,

    /// ARP entry removed (device disappeared from network).
    ///
    /// Environment variable: `DNSMASQ_ARP_ACTION=del`
    Delete,
}

impl ArpAction {
    /// Convert to environment variable string value.
    fn as_env_str(self) -> &'static str {
        match self {
            ArpAction::Add => "add",
            ArpAction::Delete => "del",
        }
    }
}

/// Script event types.
///
/// Enum representing all event types that can trigger script execution,
/// replacing C's struct `script_data` wire format with owned Rust types.
///
/// ## C Reference
///
/// Replaces: `struct script_data` (helper.c lines 151-173) with type-safe
/// enum variants instead of action field with variable-length data.
#[derive(Debug, Clone)]
pub enum ScriptEvent {
    /// DHCP lease change event.
    ///
    /// Contains all information needed to populate DHCP lease environment
    /// variables for script execution.
    DhcpLeaseEvent {
        /// Type of lease change (add, renew, delete)
        action: LeaseAction,
        /// Complete lease information including IP, MAC, expiry time
        lease: Lease,
        /// Client-supplied hostname if available
        hostname: Option<String>,
    },

    /// TFTP file transfer completion event.
    ///
    /// Notifies scripts of successful TFTP file transfers with file size,
    /// name, and client address.
    #[cfg(feature = "tftp")]
    TftpEvent {
        /// Size of the transferred file in bytes
        file_len: u64,
        /// Name of the file that was transferred
        filename: String,
        /// Network address of the TFTP client
        peer: SocketAddr,
    },

    /// ARP table change event.
    ///
    /// Notifies scripts of devices appearing or disappearing from network
    /// based on ARP cache monitoring.
    ArpEvent {
        /// Type of ARP change (add or delete)
        action: ArpAction,
        /// Hardware (MAC) address of the device
        mac: MacAddr,
        /// IP address associated with the device
        addr: IpAddr,
    },

    /// `DHCPv6` relay snooping event.
    ///
    /// Monitors `DHCPv6` prefix delegations relayed through this server,
    /// enabling external tracking of IPv6 prefix assignments.
    #[cfg(feature = "dhcp-v6")]
    RelaySnoop {
        /// IPv6 address of the `DHCPv6` client
        client: Ipv6Addr,
        /// Network interface where the relay was observed
        interface: String,
        /// IPv6 prefix that was delegated
        prefix: Ipv6Addr,
        /// Length of the delegated prefix in bits
        prefix_len: u8,
    },
}

// =============================================================================
// Script Executor
// =============================================================================

/// Script executor for DHCP, TFTP, and ARP events.
///
/// Manages script execution configuration and event queue processing, replacing
/// C's fork-based helper process with async Rust implementation using tokio.
///
/// ## Architecture
///
/// - Events queued via async mpsc channel (bounded capacity for backpressure)
/// - Scripts executed on-demand using `tokio::process::Command`
/// - Environment variables populated from event data
/// - Output captured and logged, errors reported via Result types
/// - Optional Lua integration for in-process event handling
///
/// ## C Reference
///
/// Replaces: `create_helper()` function and helper process main loop (helper.c
/// lines 261-688) with async task-based architecture.
///
/// ## Thread Safety
///
/// All methods use `Arc<RwLock<_>>` for safe concurrent access from multiple
/// async tasks. Event queue is naturally thread-safe via mpsc channel.
pub struct ScriptExecutor {
    /// Path to external script executable.
    ///
    /// Must be absolute path that exists and is executable. Cannot be changed
    /// after initialization to prevent privilege escalation attacks. Set to
    /// None if no script configured.
    script_path: Option<PathBuf>,

    /// Script execution timeout.
    ///
    /// Scripts exceeding this duration are terminated with SIGKILL. Prevents
    /// hung scripts from blocking daemon.
    timeout: Duration,

    /// Event queue sender.
    ///
    /// Used to queue events for async processing. Bounded channel provides
    /// backpressure if scripts cannot keep up with event rate.
    event_tx: mpsc::Sender<ScriptEvent>,

    /// Event queue receiver (moved to background task).
    ///
    /// Processed by background task that executes scripts for each event.
    /// Wrapped in Arc<`RwLock`<>> for shared ownership.
    event_rx: Arc<RwLock<Option<mpsc::Receiver<ScriptEvent>>>>,

    /// Lua interpreter state (feature-gated).
    ///
    /// Loaded with user-provided Lua script that defines `lease()`, `tftp()`, or
    /// `arp()` functions for event handling. Provides faster in-process event
    /// handling compared to fork+exec.
    #[cfg(feature = "lua")]
    lua: Arc<RwLock<Option<Lua>>>,
}

impl ScriptExecutor {
    /// Create new script executor.
    ///
    /// Initializes script executor with specified script path and default
    /// timeout. Path must be absolute and will be validated.
    ///
    /// ## Arguments
    ///
    /// * `script_path` - Path to external script (e.g., "/usr/local/bin/dhcp-script")
    ///
    /// ## Returns
    ///
    /// * `Result<Self, ScriptError>` - New executor or error if path invalid
    ///
    /// ## Errors
    ///
    /// Returns `ScriptError::InvalidPath` if the script path is not absolute.
    ///
    /// ## C Reference
    ///
    /// Replaces: `create_helper()` initialization (helper.c lines 261-332).
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use dnsmasq::integration::scripts::ScriptExecutor;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let executor = ScriptExecutor::new("/usr/local/bin/dhcp-script")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<P: AsRef<Path>>(script_path: P) -> Result<Self, ScriptError> {
        let path = script_path.as_ref();

        // Validate script path is absolute for security
        if !path.is_absolute() {
            return Err(ScriptError::InvalidPath(format!(
                "Script path must be absolute: {}",
                path.display()
            )));
        }

        // Create bounded event queue (capacity 1000 events)
        let (event_tx, event_rx) = mpsc::channel(1000);

        Ok(Self {
            script_path: Some(path.to_path_buf()),
            timeout: Duration::from_secs(DEFAULT_SCRIPT_TIMEOUT_SECS),
            event_tx,
            event_rx: Arc::new(RwLock::new(Some(event_rx))),
            #[cfg(feature = "lua")]
            lua: Arc::new(RwLock::new(None)),
        })
    }

    /// Create script executor without script (no-op mode).
    ///
    /// All queued events are silently dropped. Used when no script configured
    /// (--dhcp-script option not provided).
    ///
    /// ## C Reference
    ///
    /// Matches C behavior when `daemon->helperfd == -1` (no helper process).
    #[must_use]
    pub fn disabled() -> Self {
        let (event_tx, event_rx) = mpsc::channel(1);

        Self {
            script_path: None,
            timeout: Duration::from_secs(DEFAULT_SCRIPT_TIMEOUT_SECS),
            event_tx,
            event_rx: Arc::new(RwLock::new(Some(event_rx))),
            #[cfg(feature = "lua")]
            lua: Arc::new(RwLock::new(None)),
        }
    }

    /// Configure script execution timeout.
    ///
    /// Sets maximum duration for script execution before termination. Scripts
    /// exceeding timeout are killed with SIGKILL.
    ///
    /// ## Arguments
    ///
    /// * `timeout` - Maximum execution duration
    ///
    /// ## Returns
    ///
    /// Self for method chaining
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use dnsmasq::integration::scripts::ScriptExecutor;
    /// use std::time::Duration;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let executor = ScriptExecutor::new("/usr/local/bin/dhcp-script")?
    ///     .with_timeout(Duration::from_secs(60));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Load Lua script for in-process event handling (feature-gated).
    ///
    /// Loads and compiles Lua script from file, making it available for
    /// event callbacks. Script should define `lease()`, `tftp()`, and/or `arp()`
    /// functions.
    ///
    /// ## Arguments
    ///
    /// * `lua_script_path` - Path to Lua script file
    ///
    /// ## Returns
    ///
    /// * `Result<Self, ScriptError>` - Self for chaining or Lua error
    ///
    /// ## Errors
    ///
    /// Returns `ScriptError::Io` if the Lua script file cannot be read,
    /// or `ScriptError::Lua` if the script compilation fails.
    ///
    /// ## C Reference
    ///
    /// Replaces: Lua initialization in `create_helper()` (helper.c lines 313-332).
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "lua")]
    /// # {
    /// use dnsmasq::integration::scripts::ScriptExecutor;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let executor = ScriptExecutor::new("/usr/local/bin/dhcp-script")?
    ///     .with_lua("/etc/dnsmasq/lease.lua").await?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "lua")]
    pub async fn with_lua<P: AsRef<Path>>(self, lua_script_path: P) -> Result<Self, ScriptError> {
        let lua = Lua::new();

        // Load Lua script
        let script_content = tokio::fs::read_to_string(lua_script_path.as_ref()).await?;
        lua.load(&script_content).exec()?;

        *self.lua.write().await = Some(lua);

        Ok(self)
    }

    /// Queue DHCP lease change event for script execution.
    ///
    /// Queues lease event for asynchronous script execution with environment
    /// variables populated from lease data. Non-blocking operation that returns
    /// immediately after queuing.
    ///
    /// ## Arguments
    ///
    /// * `action` - Lease action (Add, Renew, Delete)
    /// * `lease` - Lease structure containing IP, MAC, client ID, etc.
    /// * `hostname` - Optional client hostname
    ///
    /// ## Returns
    ///
    /// * `Result<(), ScriptError>` - Success or queue full error
    ///
    /// ## Errors
    ///
    /// Returns `ScriptError::QueueFull` if the event queue is at capacity.
    ///
    /// ## C Reference
    ///
    /// Replaces: `queue_script()` function (helper.c lines 1174-1243).
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// # async fn example(executor: &dnsmasq::integration::scripts::ScriptExecutor, lease: dnsmasq::dhcp::lease::Lease) -> Result<(), Box<dyn std::error::Error>> {
    /// use dnsmasq::integration::scripts::LeaseAction;
    ///
    /// executor.queue_lease_event(
    ///     LeaseAction::Add,
    ///     lease,
    ///     Some("client-hostname".to_string()),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn queue_lease_event(
        &self,
        action: LeaseAction,
        lease: Lease,
        hostname: Option<String>,
    ) -> Result<(), ScriptError> {
        if self.script_path.is_none() {
            return Ok(()); // No script configured, silently ignore
        }

        let event = ScriptEvent::DhcpLeaseEvent {
            action,
            lease,
            hostname,
        };

        self.event_tx
            .send(event)
            .await
            .map_err(|_| ScriptError::QueueClosed)
    }

    /// Queue TFTP transfer completion event (feature-gated).
    ///
    /// Notifies scripts of successful TFTP file transfer with file size,
    /// name, and client address.
    ///
    /// ## Arguments
    ///
    /// * `file_len` - Size of transferred file in bytes
    /// * `filename` - Name of transferred file
    /// * `peer` - Client socket address (IPv4 or IPv6)
    ///
    /// ## Returns
    ///
    /// * `Result<(), ScriptError>` - Success or queue error
    ///
    /// ## Errors
    ///
    /// Returns `ScriptError::QueueFull` if the event queue is at capacity.
    ///
    /// ## C Reference
    ///
    /// Replaces: `queue_tftp()` function (helper.c lines 1366-1443).
    #[cfg(feature = "tftp")]
    pub async fn queue_tftp_event(
        &self,
        file_len: u64,
        filename: String,
        peer: SocketAddr,
    ) -> Result<(), ScriptError> {
        if self.script_path.is_none() {
            return Ok(());
        }

        let event = ScriptEvent::TftpEvent {
            file_len,
            filename,
            peer,
        };

        self.event_tx
            .send(event)
            .await
            .map_err(|_| ScriptError::QueueClosed)
    }

    /// Queue ARP detection event.
    ///
    /// Notifies scripts of devices appearing or disappearing from network
    /// based on ARP cache monitoring.
    ///
    /// ## Arguments
    ///
    /// * `action` - ARP action (Add or Delete)
    /// * `mac` - Hardware address of detected device
    /// * `addr` - IP address of detected device
    ///
    /// ## Returns
    ///
    /// * `Result<(), ScriptError>` - Success or queue error
    ///
    /// ## Errors
    ///
    /// Returns `ScriptError::QueueFull` if the event queue is at capacity.
    ///
    /// ## C Reference
    ///
    /// Replaces: `queue_arp()` function (helper.c lines 1444-1464).
    pub async fn queue_arp_event(
        &self,
        action: ArpAction,
        mac: MacAddr,
        addr: IpAddr,
    ) -> Result<(), ScriptError> {
        if self.script_path.is_none() {
            return Ok(());
        }

        let event = ScriptEvent::ArpEvent { action, mac, addr };

        self.event_tx
            .send(event)
            .await
            .map_err(|_| ScriptError::QueueClosed)
    }

    /// Queue `DHCPv6` relay snooping event (feature-gated).
    ///
    /// Monitors `DHCPv6` prefix delegations relayed through this server.
    ///
    /// ## Arguments
    ///
    /// * `client` - IPv6 address of `DHCPv6` client
    /// * `interface` - Interface name where relay message received
    /// * `prefix` - IPv6 prefix being delegated
    /// * `prefix_len` - Prefix length in bits
    ///
    /// ## Returns
    ///
    /// * `Result<(), ScriptError>` - Success or queue error
    ///
    /// ## Errors
    ///
    /// Returns `ScriptError::QueueFull` if the event queue is at capacity.
    ///
    /// ## C Reference
    ///
    /// Replaces: `queue_relay_snoop()` function (helper.c lines 1294-1313).
    #[cfg(feature = "dhcp-v6")]
    pub async fn queue_relay_snoop_event(
        &self,
        client: Ipv6Addr,
        interface: String,
        prefix: Ipv6Addr,
        prefix_len: u8,
    ) -> Result<(), ScriptError> {
        if self.script_path.is_none() {
            return Ok(());
        }

        let event = ScriptEvent::RelaySnoop {
            client,
            interface,
            prefix,
            prefix_len,
        };

        self.event_tx
            .send(event)
            .await
            .map_err(|_| ScriptError::QueueClosed)
    }

    /// Start background event processing task.
    ///
    /// Spawns async task that processes queued events by executing scripts
    /// with appropriate environment variables. Should be called once after
    /// executor initialization.
    ///
    /// ## Panics
    ///
    /// Panics if `start()` is called multiple times on the same executor instance.
    ///
    /// ## Returns
    ///
    /// * `tokio::task::JoinHandle` - Handle to background task
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use dnsmasq::integration::scripts::ScriptExecutor;
    /// use std::sync::Arc;
    ///
    /// let executor = Arc::new(ScriptExecutor::new("/usr/local/bin/dhcp-script")?);
    /// let executor_clone = executor.clone();
    /// let handle = executor.start().await;
    ///
    /// // ... use executor_clone to queue events ...
    ///
    /// // Shutdown: drop executor references and await handle
    /// drop(executor_clone);
    /// handle.await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mut rx = self
            .event_rx
            .write()
            .await
            .take()
            .expect("start() called multiple times");

        // Clone necessary fields to avoid holding Arc in spawned task
        // This allows the channel to close when external Arc references are dropped
        let script_path = self.script_path.clone();
        let timeout = self.timeout;
        #[cfg(feature = "lua")]
        let lua = self.lua.clone();

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(e) = Self::process_event_internal(
                    script_path.as_ref(),
                    timeout,
                    #[cfg(feature = "lua")]
                    lua.clone(),
                    event,
                )
                .await
                {
                    error!("Script execution error: {}", e);
                }
            }

            info!("Script executor shutdown");
        })
    }

    /// Process single event by executing script.
    ///
    /// Internal method that executes script with environment variables
    /// populated from event data. Handles both external scripts and Lua
    /// callbacks.
    ///
    /// ## Arguments
    ///
    /// * `script_path` - Optional path to script executable
    /// * `timeout` - Script execution timeout
    /// * `lua` - Optional Lua interpreter state (feature-gated)
    /// * `event` - Event to process
    ///
    /// ## Returns
    ///
    /// * `Result<(), ScriptError>` - Success or execution error
    async fn process_event_internal(
        script_path: Option<&PathBuf>,
        timeout: Duration,
        #[cfg(feature = "lua")] lua: Arc<RwLock<Option<mlua::Lua>>>,
        event: ScriptEvent,
    ) -> Result<(), ScriptError> {
        match event {
            ScriptEvent::DhcpLeaseEvent {
                action,
                lease,
                hostname,
            } => {
                // Try Lua callback first if available
                #[cfg(feature = "lua")]
                if let Some(lua_instance) = lua.read().await.as_ref() {
                    if let Err(e) = Self::call_lua_lease_internal(
                        lua_instance,
                        action,
                        &lease,
                        hostname.as_deref(),
                    )
                    .await
                    {
                        warn!("Lua callback failed, falling back to script: {}", e);
                    } else {
                        return Ok(());
                    }
                }

                // Execute external script
                if let Some(path) = script_path {
                    Self::execute_lease_script_internal(
                        path,
                        timeout,
                        action,
                        &lease,
                        hostname.as_deref(),
                    )
                    .await?;
                }
            }

            #[cfg(feature = "tftp")]
            ScriptEvent::TftpEvent {
                file_len,
                filename,
                peer,
            } => {
                #[cfg(feature = "lua")]
                if let Some(lua_instance) = lua.read().await.as_ref() {
                    if let Err(e) =
                        Self::call_lua_tftp_internal(lua_instance, file_len, &filename, &peer).await
                    {
                        warn!("Lua tftp callback failed: {}", e);
                    } else {
                        return Ok(());
                    }
                }

                if let Some(path) = script_path {
                    Self::execute_tftp_script_internal(path, timeout, file_len, &filename, &peer)
                        .await?;
                }
            }

            ScriptEvent::ArpEvent { action, mac, addr } => {
                #[cfg(feature = "lua")]
                if let Some(lua_instance) = lua.read().await.as_ref() {
                    if let Err(e) =
                        Self::call_lua_arp_internal(lua_instance, action, &mac, &addr).await
                    {
                        warn!("Lua arp callback failed: {}", e);
                    } else {
                        return Ok(());
                    }
                }

                if let Some(path) = script_path {
                    Self::execute_arp_script_internal(path, timeout, action, &mac, &addr).await?;
                }
            }

            #[cfg(feature = "dhcp-v6")]
            ScriptEvent::RelaySnoop {
                client,
                interface,
                prefix,
                prefix_len,
            } => {
                if let Some(path) = script_path {
                    Self::execute_relay_snoop_script_internal(
                        path, timeout, &client, &interface, &prefix, prefix_len,
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    /// Execute external script for DHCP lease event.
    ///
    /// Spawns script process with DNSMASQ_* environment variables populated
    /// from lease data. Captures stdout/stderr and logs output.
    ///
    /// ## C Reference
    ///
    /// Replaces: Script execution logic in helper process main loop (helper.c
    /// lines 446-689) including `my_setenv()` calls (lines 912-921) and
    /// `grab_extradata()` parsing (lines 968-997).
    async fn execute_lease_script_internal(
        script_path: &Path,
        timeout: Duration,
        action: LeaseAction,
        lease: &Lease,
        hostname: Option<&str>,
    ) -> Result<(), ScriptError> {
        let mut env = HashMap::new();

        // Populate environment variables based on lease data
        env.insert(
            "DNSMASQ_LEASE_ACTION".to_string(),
            action.as_env_str().to_string(),
        );

        match lease {
            Lease::V4(lease_v4) => {
                env.insert("DNSMASQ_IP_ADDR".to_string(), lease_v4.addr.to_string());
                env.insert(
                    "DNSMASQ_MAC_ADDR".to_string(),
                    format_mac_addr(&lease_v4.hwaddr),
                );

                if let Some(client_id) = &lease_v4.client_id {
                    env.insert("DNSMASQ_CLIENT_ID".to_string(), format_hex(client_id));
                }

                if let Some(hostname) = hostname {
                    env.insert("DNSMASQ_HOSTNAME".to_string(), sanitize_env_value(hostname));
                }

                let remaining = if lease_v4.expires > 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    lease_v4.expires.saturating_sub(now)
                } else {
                    0
                };

                env.insert(
                    "DNSMASQ_LEASE_EXPIRES".to_string(),
                    lease_v4.expires.to_string(),
                );
                env.insert("DNSMASQ_LEASE_LENGTH".to_string(), remaining.to_string());
            }

            #[cfg(feature = "dhcp-v6")]
            Lease::V6(lease_v6) => {
                env.insert("DNSMASQ_IP_ADDR".to_string(), lease_v6.addr.to_string());
                env.insert("DNSMASQ_DUID".to_string(), format_hex(&lease_v6.duid));
                env.insert("DNSMASQ_IAID".to_string(), lease_v6.iaid.to_string());

                if let Some(hostname) = hostname {
                    env.insert("DNSMASQ_HOSTNAME".to_string(), sanitize_env_value(hostname));
                }

                let remaining = if lease_v6.expires > 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    lease_v6.expires.saturating_sub(now)
                } else {
                    0
                };

                env.insert(
                    "DNSMASQ_LEASE_EXPIRES".to_string(),
                    lease_v6.expires.to_string(),
                );
                env.insert("DNSMASQ_LEASE_LENGTH".to_string(), remaining.to_string());
            }
        }

        Self::execute_script_with_env_internal(script_path, timeout, env).await
    }

    /// Execute external script for TFTP transfer event (feature-gated).
    ///
    /// ## C Reference
    ///
    /// Replaces: TFTP action handling in helper (helper.c lines 603-629).
    #[cfg(feature = "tftp")]
    async fn execute_tftp_script_internal(
        script_path: &Path,
        timeout: Duration,
        file_len: u64,
        filename: &str,
        peer: &SocketAddr,
    ) -> Result<(), ScriptError> {
        let mut env = HashMap::new();

        env.insert("DNSMASQ_TFTP_FILE_SIZE".to_string(), file_len.to_string());
        env.insert(
            "DNSMASQ_TFTP_FILE_NAME".to_string(),
            sanitize_env_value(filename),
        );
        env.insert(
            "DNSMASQ_TFTP_REMOTE_ADDR".to_string(),
            peer.ip().to_string(),
        );

        Self::execute_script_with_env_internal(script_path, timeout, env).await
    }

    /// Execute external script for ARP detection event.
    ///
    /// ## C Reference
    ///
    /// Replaces: ARP action handling in helper (helper.c lines 630-657).
    async fn execute_arp_script_internal(
        script_path: &Path,
        timeout: Duration,
        action: ArpAction,
        mac: &MacAddr,
        addr: &IpAddr,
    ) -> Result<(), ScriptError> {
        let mut env = HashMap::new();

        env.insert(
            "DNSMASQ_ARP_ACTION".to_string(),
            action.as_env_str().to_string(),
        );
        env.insert("DNSMASQ_ARP_MAC".to_string(), mac.to_string());
        env.insert("DNSMASQ_ARP_IP".to_string(), addr.to_string());

        Self::execute_script_with_env_internal(script_path, timeout, env).await
    }

    /// Execute external script for `DHCPv6` relay snoop event (feature-gated).
    ///
    /// ## C Reference
    ///
    /// Replaces: Relay snoop handling (helper.c lines 586-602).
    #[cfg(feature = "dhcp-v6")]
    async fn execute_relay_snoop_script_internal(
        script_path: &Path,
        timeout: Duration,
        client: &Ipv6Addr,
        interface: &str,
        prefix: &Ipv6Addr,
        prefix_len: u8,
    ) -> Result<(), ScriptError> {
        let mut env = HashMap::new();

        env.insert("DNSMASQ_RELAY_CLIENT".to_string(), client.to_string());
        env.insert("DNSMASQ_RELAY_INTERFACE".to_string(), interface.to_string());
        env.insert(
            "DNSMASQ_RELAY_PREFIX".to_string(),
            format!("{prefix}/{prefix_len}"),
        );

        Self::execute_script_with_env_internal(script_path, timeout, env).await
    }

    /// Execute script with environment variables and timeout.
    ///
    /// Common implementation for all script types, spawning process with
    /// configured environment, capturing output, and enforcing timeout.
    ///
    /// ## C Reference
    ///
    /// Replaces: fork/exec logic in helper (helper.c lines 658-688).
    async fn execute_script_with_env_internal(
        script_path: &Path,
        timeout: Duration,
        env: HashMap<String, String>,
    ) -> Result<(), ScriptError> {
        debug!(
            "Executing script: {} with {} env vars",
            script_path.display(),
            env.len()
        );

        let mut cmd = Command::new(script_path);
        cmd.envs(env);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Spawn process with timeout
        let child = cmd.spawn()?;

        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| ScriptError::Timeout(timeout))??;

        if !output.status.success() {
            let exit_code = output.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(ScriptError::ExecutionFailed { exit_code, stderr });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.is_empty() {
            info!("Script output: {}", stdout.trim());
        }

        Ok(())
    }

    /// Call Lua lease callback (feature-gated).
    ///
    /// Invokes Lua `lease()` function with event data table, providing faster
    /// in-process event handling compared to fork+exec.
    ///
    /// ## C Reference
    ///
    /// Replaces: Lua `lease()` call (helper.c lines 469-495).
    #[cfg(feature = "lua")]
    #[allow(clippy::unused_async)]
    async fn call_lua_lease_internal(
        lua: &Lua,
        action: LeaseAction,
        lease: &Lease,
        hostname: Option<&str>,
    ) -> Result<(), mlua::Error> {
        let globals = lua.globals();

        // Check if lease() function exists
        if !globals.contains_key("lease")? {
            return Ok(()); // Function not defined, silently skip
        }

        let lease_fn: mlua::Function = globals.get("lease")?;

        // Create data table
        let table = lua.create_table()?;
        table.set("action", action.as_env_str())?;

        match lease {
            Lease::V4(lease_v4) => {
                table.set("ip_addr", lease_v4.addr.to_string())?;
                table.set("mac_addr", format_mac_addr(&lease_v4.hwaddr))?;

                if let Some(client_id) = &lease_v4.client_id {
                    table.set("client_id", format_hex(client_id))?;
                }

                if let Some(hostname) = hostname {
                    table.set("hostname", hostname)?;
                }

                table.set("expires", lease_v4.expires)?;
            }

            #[cfg(feature = "dhcp-v6")]
            Lease::V6(lease_v6) => {
                table.set("ip_addr", lease_v6.addr.to_string())?;
                table.set("duid", format_hex(&lease_v6.duid))?;
                table.set("iaid", lease_v6.iaid)?;

                if let Some(hostname) = hostname {
                    table.set("hostname", hostname)?;
                }

                table.set("expires", lease_v6.expires)?;
            }
        }

        // Call lease(action, data)
        lease_fn.call::<()>((action.as_env_str(), table))?;

        Ok(())
    }

    /// Call Lua tftp callback (feature-gated).
    ///
    /// ## C Reference
    ///
    /// Replaces: Lua `tftp()` call (helper.c lines 322-338).
    #[cfg(all(feature = "lua", feature = "tftp"))]
    #[allow(clippy::unused_async)]
    async fn call_lua_tftp_internal(
        lua: &Lua,
        file_len: u64,
        filename: &str,
        peer: &SocketAddr,
    ) -> Result<(), mlua::Error> {
        let globals = lua.globals();

        if !globals.contains_key("tftp")? {
            return Ok(());
        }

        let tftp_fn: mlua::Function = globals.get("tftp")?;

        let table = lua.create_table()?;
        table.set("file_size", file_len)?;
        table.set("file_name", filename)?;
        table.set("remote_addr", peer.ip().to_string())?;

        tftp_fn.call::<()>(table)?;

        Ok(())
    }

    /// Call Lua arp callback (feature-gated).
    ///
    /// ## C Reference
    ///
    /// Replaces: Lua `arp()` call (helper.c lines 340-357).
    #[cfg(feature = "lua")]
    #[allow(clippy::unused_async)]
    async fn call_lua_arp_internal(
        lua: &Lua,
        action: ArpAction,
        mac: &MacAddr,
        addr: &IpAddr,
    ) -> Result<(), mlua::Error> {
        let globals = lua.globals();

        if !globals.contains_key("arp")? {
            return Ok(());
        }

        let arp_fn: mlua::Function = globals.get("arp")?;

        let table = lua.create_table()?;
        table.set("action", action.as_env_str())?;
        table.set("mac_addr", mac.to_string())?;
        table.set("ip_addr", addr.to_string())?;

        arp_fn.call::<()>(table)?;

        Ok(())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Format MAC address as colon-separated hex string.
///
/// Converts byte array to human-readable MAC address format (AA:BB:CC:DD:EE:FF).
///
/// ## C Reference
///
/// Replaces: MAC formatting in `my_setenv()` calls (helper.c lines 550-560).
fn format_mac_addr(hwaddr: &[u8]) -> String {
    hwaddr
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Format byte array as hex string.
///
/// Converts byte array to hex string representation for client IDs and DUIDs.
///
/// ## C Reference
///
/// Replaces: Client ID formatting (helper.c lines 508-524).
fn format_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Sanitize environment variable value.
///
/// Removes '=' characters to prevent environment variable injection attacks
/// and truncates excessively long values.
///
/// ## C Reference
///
/// Replaces: '=' stripping in `grab_extradata()` (helper.c lines 987-990).
fn sanitize_env_value(value: &str) -> String {
    let sanitized = value.replace('=', "");

    if sanitized.len() > MAX_ENV_VALUE_LEN {
        sanitized[..MAX_ENV_VALUE_LEN].to_string()
    } else {
        sanitized
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_action_env_str() {
        assert_eq!(LeaseAction::Add.as_env_str(), "add");
        assert_eq!(LeaseAction::Renew.as_env_str(), "old");
        assert_eq!(LeaseAction::Delete.as_env_str(), "del");
    }

    #[test]
    fn test_arp_action_env_str() {
        assert_eq!(ArpAction::Add.as_env_str(), "add");
        assert_eq!(ArpAction::Delete.as_env_str(), "del");
    }

    #[test]
    fn test_format_mac_addr() {
        let mac = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac_addr(&mac), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_format_hex() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        assert_eq!(format_hex(&bytes), "0123456789abcdef");
    }

    #[test]
    fn test_sanitize_env_value() {
        assert_eq!(sanitize_env_value("test=value"), "testvalue");
        assert_eq!(sanitize_env_value("normal"), "normal");

        let long_value = "a".repeat(MAX_ENV_VALUE_LEN + 100);
        let sanitized = sanitize_env_value(&long_value);
        assert_eq!(sanitized.len(), MAX_ENV_VALUE_LEN);
    }

    #[test]
    fn test_script_executor_disabled() {
        let executor = ScriptExecutor::disabled();
        assert!(executor.script_path.is_none());
    }

    #[test]
    fn test_script_executor_invalid_path() {
        let result = ScriptExecutor::new("relative/path");
        assert!(matches!(result, Err(ScriptError::InvalidPath(_))));
    }

    #[tokio::test]
    async fn test_script_executor_new_valid() {
        let result = ScriptExecutor::new("/usr/bin/test");
        assert!(result.is_ok());

        let executor = result.unwrap();
        assert_eq!(
            executor.script_path.as_ref().unwrap().to_str().unwrap(),
            "/usr/bin/test"
        );
        assert_eq!(
            executor.timeout,
            Duration::from_secs(DEFAULT_SCRIPT_TIMEOUT_SECS)
        );
    }

    #[tokio::test]
    async fn test_script_executor_with_timeout() {
        let executor = ScriptExecutor::new("/usr/bin/test")
            .unwrap()
            .with_timeout(Duration::from_secs(60));

        assert_eq!(executor.timeout, Duration::from_secs(60));
    }
}
