// Copyright (C) 2024 Dnsmasq Contributors
// SPDX-License-Identifier: GPL-2.0-or-later

//! Helper process for DHCP lease-change script execution
//!
//! This module translates C's privileged helper process architecture from `helper.c` to Rust's
//! async task model. The original C implementation uses `fork()`+`pipe()` for privilege separation,
//! where a helper process retains elevated privileges to execute external scripts while the main
//! daemon drops to an unprivileged user. This Rust implementation replaces that with tokio tasks
//! and channels while maintaining the same security model and script invocation semantics.
//!
//! # Architecture
//!
//! The helper system provides a way to execute external scripts or Lua functions in response to
//! DHCP lease events (`add`/`old`/`del`), TFTP transfers, ARP detections, and `DHCPv6` relay events.
//! Events are serialized and sent through a tokio channel to a long-running helper task that:
//!
//! 1. Deserializes the event
//! 2. Prepares environment variables (for script mode) or Lua table (for Lua mode)
//! 3. Spawns the script process or calls the Lua function
//! 4. Captures stdout/stderr for logging
//! 5. Reports completion status or errors
//!
//! # Privilege Separation
//!
//! In the C implementation, the helper process is forked before the main daemon drops privileges,
//! allowing scripts to run with elevated permissions if needed. In this Rust implementation:
//!
//! - The helper task should be spawned before calling privilege-dropping functions
//! - If scripts require elevated permissions, the entire process maintains those permissions
//! - For security, it's recommended to configure scripts to run as unprivileged users via
//!   systemd's `DynamicUser` or similar mechanisms
//!
//! # Script Execution
//!
//! Scripts are invoked with the command line:
//! ```text
//! <script-path> <action> <mac-or-duid> <ip-address> <hostname>
//! ```
//!
//! And environment variables:
//! - `DNSMASQ_LEASE_ACTION`: add/old/del/tftp/arp-add/arp-del
//! - `DNSMASQ_CLIENT_ID`: DHCP client identifier
//! - `DNSMASQ_INTERFACE`: Network interface name
//! - `DNSMASQ_LEASE_EXPIRES`: Lease expiry timestamp
//! - `DNSMASQ_REQUESTED_OPTIONS`: DHCP options requested by client
//! - And many more (see environment variable setup in `process_event`)
//!
//! # Lua Integration
//!
//! When the `lua` feature is enabled, Lua functions can be called instead of external scripts:
//! - `lease(action, data_table)` - for DHCP lease events
//! - `tftp(action, data_table)` - for TFTP transfers
//! - `arp(action, data_table)` - for ARP detections
//! - `snoop(action, data_table)` - for `DHCPv6` relay snooping
//!
//! # Error Handling
//!
//! All script execution errors are reported through the `HelperError` enum with context:
//! - Failed to spawn: Script path invalid or permissions issue
//! - Timeout: Script exceeded configured timeout (default: 60 seconds)
//! - Non-zero exit: Script returned error code
//! - Channel closed: Helper task terminated unexpectedly
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use dnsmasq::runtime::{spawn_helper_process, ScriptEvent};
//! use std::path::PathBuf;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Spawn helper task with script configuration
//! let handle = spawn_helper_process(
//!     Some(PathBuf::from("/etc/dnsmasq/lease-change.sh")),
//!     &None, // No Lua script
//!     Duration::from_secs(60),
//! )?;
//!
//! // Send DHCP lease event
//! let event = ScriptEvent::DhcpLease {
//!     mac: "00:11:22:33:44:55".to_string(),
//!     ip: "192.168.1.100".to_string(),
//!     hostname: "client-host".to_string(),
//!     interface: "eth0".to_string(),
//!     expiry: 1234567890,
//!     client_id: Some("client-id-hex".to_string()),
//!     tags: Box::new(vec!["tag1".to_string()]),
//!     vendor_class: None,
//!     supplied_hostname: Some("client-supplied".to_string()),
//!     circuit_id: None,
//!     remote_id: None,
//!     subscriber_id: None,
//!     relay_address: None,
//!     user_classes: Box::new(vec![]),
//!     time_remaining: 3600,
//!     old_hostname: None,
//! };
//!
//! handle.send_event(event)?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, error, info, warn};

#[cfg(feature = "lua")]
use mlua::Lua;

/// Default script execution timeout (60 seconds, matching C implementation's alarm behavior)
const DEFAULT_SCRIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Script event data for DHCP leases, TFTP transfers, ARP detections, and relay snooping
///
/// This enum represents all possible events that can trigger script or Lua function execution.
/// Each variant contains the data necessary to populate environment variables (for scripts) or
/// Lua table fields (for Lua functions). The structure matches the wire format from `helper.c`'s
/// `struct script_data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ScriptEvent {
    /// DHCP lease addition (action: "add")
    ///
    /// Triggered when a new DHCP lease is created. Contains complete lease information including
    /// client identifiers, hostname, expiry time, and DHCP options extracted from the client's
    /// DISCOVER/REQUEST messages.
    DhcpLease {
        /// MAC address in colon-separated hex format (e.g., "00:11:22:33:44:55")
        mac: String,
        /// IP address assigned to client
        ip: String,
        /// Hostname associated with lease (may be from DHCP option 12 or DNS)
        hostname: String,
        /// Network interface name where lease was created
        interface: String,
        /// Lease expiry timestamp (Unix epoch seconds)
        expiry: u64,
        /// DHCP client identifier (option 61) in hex format, if present
        client_id: Option<String>,
        /// DHCP tags configured for this lease
        tags: Box<Vec<String>>,
        /// Vendor class identifier (`option 60` for `DHCPv4`, `option 16` for `DHCPv6`)
        vendor_class: Option<String>,
        /// Hostname supplied by client in DHCP option 12
        supplied_hostname: Option<String>,
        /// Circuit ID from DHCP relay agent (option 82 suboption 1)
        circuit_id: Option<String>,
        /// Remote ID from DHCP relay agent (option 82 suboption 2)
        remote_id: Option<String>,
        /// Subscriber ID from DHCP relay agent
        subscriber_id: Option<String>,
        /// Relay agent IP address (`giaddr` for `DHCPv4`, relay `link-address` for `DHCPv6`)
        relay_address: Option<String>,
        /// User class options (option 77) sent by client
        user_classes: Box<Vec<String>>,
        /// Time remaining until lease expires (seconds)
        time_remaining: u32,
        /// Old hostname if this is an `ACTION_OLD_HOSTNAME` event
        old_hostname: Option<String>,
    },

    /// DHCP lease renewal with existing IP (action: "old")
    ///
    /// Triggered when a client renews an existing lease without changing IP address. Contains
    /// subset of `DhcpLease` fields as not all options are re-transmitted during renewals.
    DhcpLeaseOld {
        /// MAC address
        mac: String,
        /// IP address (unchanged from previous lease)
        ip: String,
        /// Hostname
        hostname: String,
        /// Network interface
        interface: String,
        /// New expiry timestamp
        expiry: u64,
        /// Client identifier
        client_id: Option<String>,
    },

    /// DHCP lease deletion (action: "del")
    ///
    /// Triggered when a lease expires, is released by client (DHCPRELEASE), or is manually
    /// deleted. No expiry time is included as the lease is already invalid.
    DhcpLeaseDel {
        /// MAC address
        mac: String,
        /// IP address being released
        ip: String,
        /// Hostname
        hostname: String,
        /// Network interface
        interface: String,
    },

    /// TFTP file transfer completion (action: "tftp")
    ///
    /// Triggered when a TFTP file transfer completes successfully. Useful for tracking PXE boot
    /// activity and network boot file distribution.
    TftpTransfer {
        /// Size of transferred file in bytes
        file_size: u64,
        /// IP address of TFTP client
        destination: String,
        /// Filename requested by client (relative to TFTP root)
        filename: String,
        /// Network interface (may be empty for TFTP)
        interface: String,
    },

    /// ARP address addition (action: "arp-add")
    ///
    /// Triggered when an IP address is detected via ARP without a corresponding DHCP lease.
    /// Allows tracking of statically-configured hosts or DHCP leases from other servers.
    ArpAdd {
        /// MAC address in hex format
        mac: String,
        /// IPv4 address detected
        ip: String,
        /// Network interface
        interface: String,
    },

    /// ARP address deletion (action: "arp-del")
    ///
    /// Triggered when an ARP entry expires or is removed.
    ArpDel {
        /// MAC address
        mac: String,
        /// IPv4 address
        ip: String,
        /// Network interface
        interface: String,
    },

    /// `DHCPv6` relay snooping (action: "relay-snoop")
    ///
    /// Triggered when `dnsmasq` observes `DHCPv6` messages relayed through it, useful for tracking
    /// IPv6 prefix delegations and client bindings in relay scenarios.
    RelaySnoop {
        /// Client IPv6 address
        client_address: String,
        /// Delegated prefix in CIDR notation (e.g., `2001:db8::/64`)
        prefix: String,
        /// Network interface where relay message was received
        interface: String,
    },
}

impl ScriptEvent {
    /// Get the action string for this event
    ///
    /// Returns the action string that will be passed as the first command-line argument to
    /// scripts and as the first parameter to Lua functions. Matches the action strings from
    /// `helper.c` (lines 396-423).
    #[must_use]
    pub fn action(&self) -> &str {
        match self {
            ScriptEvent::DhcpLease { .. } => "add",
            ScriptEvent::DhcpLeaseOld { .. } => "old",
            ScriptEvent::DhcpLeaseDel { .. } => "del",
            ScriptEvent::TftpTransfer { .. } => "tftp",
            ScriptEvent::ArpAdd { .. } => "arp-add",
            ScriptEvent::ArpDel { .. } => "arp-del",
            ScriptEvent::RelaySnoop { .. } => "relay-snoop",
        }
    }

    /// Get the MAC address or client `DUID` for script invocation
    ///
    /// Returns the hardware address that will be passed as the second command-line argument.
    /// For DHCP events, this is the MAC address; for `DHCPv6`, it's the `DUID`.
    #[must_use]
    pub fn mac_or_duid(&self) -> &str {
        match self {
            ScriptEvent::DhcpLease { mac, .. }
            | ScriptEvent::DhcpLeaseOld { mac, .. }
            | ScriptEvent::DhcpLeaseDel { mac, .. }
            | ScriptEvent::ArpAdd { mac, .. }
            | ScriptEvent::ArpDel { mac, .. } => mac,
            ScriptEvent::TftpTransfer { .. } | ScriptEvent::RelaySnoop { .. } => "",
        }
    }

    /// Get the IP address for script invocation
    ///
    /// Returns the IP address that will be passed as the third command-line argument.
    #[must_use]
    pub fn ip_address(&self) -> &str {
        match self {
            ScriptEvent::DhcpLease { ip, .. }
            | ScriptEvent::DhcpLeaseOld { ip, .. }
            | ScriptEvent::DhcpLeaseDel { ip, .. }
            | ScriptEvent::ArpAdd { ip, .. }
            | ScriptEvent::ArpDel { ip, .. } => ip,
            ScriptEvent::TftpTransfer { destination, .. } => destination,
            ScriptEvent::RelaySnoop { client_address, .. } => client_address,
        }
    }

    /// Get the hostname for script invocation
    ///
    /// Returns the hostname that will be passed as the fourth command-line argument.
    /// May be empty string if no hostname is available.
    #[must_use]
    pub fn hostname(&self) -> &str {
        match self {
            ScriptEvent::DhcpLease { hostname, .. }
            | ScriptEvent::DhcpLeaseOld { hostname, .. }
            | ScriptEvent::DhcpLeaseDel { hostname, .. } => hostname,
            ScriptEvent::TftpTransfer { filename, .. } => filename,
            ScriptEvent::RelaySnoop { prefix, .. } => prefix,
            ScriptEvent::ArpAdd { .. } | ScriptEvent::ArpDel { .. } => "",
        }
    }
}

/// Errors that can occur during helper process operations
///
/// These errors represent failures in script execution, Lua function calls, or communication
/// with the helper task. All errors include context to aid in debugging and are suitable for
/// logging with structured logging frameworks.
#[derive(Debug, Error)]
pub enum HelperError {
    /// Failed to spawn script process
    ///
    /// Indicates the script path doesn't exist, isn't executable, or spawn failed due to
    /// resource limits. Includes the script path and underlying I/O error.
    #[error("Failed to spawn script '{path}': {error}")]
    FailedToSpawnScript {
        /// Script path that failed to spawn
        path: PathBuf,
        /// Underlying I/O error
        #[source]
        error: std::io::Error,
    },

    /// Script execution exceeded timeout
    ///
    /// The script did not complete within the configured timeout period. The script process
    /// is killed automatically when the timeout expires. Default timeout is 60 seconds.
    #[error("Script timed out after {duration:?}")]
    ScriptTimeout {
        /// Configured timeout duration
        duration: Duration,
    },

    /// Script exited with non-zero status
    ///
    /// The script executed but returned an error exit code. Includes the exit code for
    /// debugging. Script stderr output is logged separately via `tracing::error!`.
    #[error("Script exited with code {code}")]
    ScriptNonZeroExit {
        /// Exit code returned by script
        code: i32,
    },

    /// Helper task channel closed
    ///
    /// The helper task terminated unexpectedly, possibly due to panic or cancellation.
    /// Events sent after this error will fail immediately. The helper task must be restarted
    /// to resume script execution.
    #[error("Helper channel closed")]
    ChannelClosed,

    /// Lua script error
    ///
    /// A Lua function call failed, either because the function doesn't exist, raised an error,
    /// or the Lua interpreter encountered a runtime error. Includes the Lua error message.
    #[cfg(feature = "lua")]
    #[error("Lua error: {0}")]
    LuaError(String),

    /// I/O error during script execution
    ///
    /// An I/O error occurred while reading script output, waiting for completion, or
    /// communicating with the script process.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Handle for communicating with the helper task
///
/// Provides methods to send events to the helper task, check if the helper is still running,
/// and gracefully shut down the helper. The handle uses a tokio unbounded channel for event
/// transmission, ensuring events are never dropped due to backpressure (though this means
/// scripts must keep up with event rate to avoid unbounded memory growth).
///
/// # Cloning
///
/// The handle can be cloned to allow multiple parts of the application to send events. All
/// clones share the same underlying channel, and the helper task continues running until all
/// clones are dropped.
#[derive(Clone)]
pub struct HelperHandle {
    sender: mpsc::UnboundedSender<ScriptEvent>,
}

impl HelperHandle {
    /// Send an event to the helper task for script execution
    ///
    /// Serializes the event and sends it to the helper task via the unbounded channel. The
    /// helper task will execute the configured script or Lua function asynchronously. This
    /// method returns immediately without waiting for script completion.
    ///
    /// # Errors
    ///
    /// Returns `HelperError::ChannelClosed` if the helper task has terminated.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dnsmasq::runtime::{HelperHandle, HelperError, ScriptEvent};
    /// # use std::path::PathBuf;
    /// # use std::time::Duration;
    /// # fn example(handle: HelperHandle) -> Result<(), HelperError> {
    /// let event = ScriptEvent::DhcpLease {
    ///     mac: "00:11:22:33:44:55".to_string(),
    ///     ip: "192.168.1.100".to_string(),
    ///     hostname: "client".to_string(),
    ///     interface: "eth0".to_string(),
    ///     expiry: 1234567890,
    ///     client_id: None,
    ///     tags: Box::new(vec![]),
    ///     vendor_class: None,
    ///     supplied_hostname: None,
    ///     circuit_id: None,
    ///     remote_id: None,
    ///     subscriber_id: None,
    ///     relay_address: None,
    ///     user_classes: Box::new(vec![]),
    ///     time_remaining: 3600,
    ///     old_hostname: None,
    /// };
    ///
    /// handle.send_event(event)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_event(&self, event: ScriptEvent) -> Result<(), HelperError> {
        self.sender
            .send(event)
            .map_err(|_| HelperError::ChannelClosed)
    }

    /// Close the helper task gracefully
    ///
    /// Drops the sender channel, causing the helper task to complete any pending events and
    /// then exit. This method returns immediately; the helper task will terminate asynchronously.
    ///
    /// After calling `close()`, any attempts to send events via cloned handles will fail with
    /// `HelperError::ChannelClosed`.
    pub fn close(self) {
        // Dropping self closes the channel
        drop(self.sender);
    }

    /// Check if the helper task is still running
    ///
    /// Returns `true` if the helper task's receiver is still active and accepting events.
    /// Returns `false` if the helper task has terminated or the channel is closed.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dnsmasq::runtime::HelperHandle;
    /// # async fn example(handle: &HelperHandle) {
    /// if !handle.is_closed() {
    ///     // Safe to send events
    /// } else {
    ///     // Helper task terminated, restart required
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}

/// Spawn the helper task for script execution
///
/// Creates a long-running tokio task that receives events via a channel and executes either
/// external scripts (if `script_path` is provided) or Lua functions (if `lua_script_path` is
/// provided and the `lua` feature is enabled). The task processes events sequentially, ensuring
/// scripts don't run concurrently (matching the C implementation's behavior).
///
/// # Parameters
///
/// * `script_path` - Path to external script executable (e.g., `/etc/dnsmasq/lease-change.sh`)
/// * `lua_script_path` - Path to Lua script file (requires `lua` feature)
/// * `script_timeout` - Maximum time to wait for script completion before killing it
///
/// # Returns
///
/// Returns a `HelperHandle` for sending events to the helper task.
///
/// # Errors
///
/// * `HelperError::LuaError` - Lua script failed to load or `lease()` function is missing
/// * `HelperError::IoError` - Failed to read Lua script file
///
/// # Panics
///
/// The spawned task will panic if script execution fails catastrophically (e.g., OOM), but
/// this is logged and doesn't affect the main application. Individual script failures are
/// reported via `tracing::error!` and don't cause task termination.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::runtime::{spawn_helper_process, HelperError};
/// use std::path::PathBuf;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), HelperError> {
/// // Script-only mode
/// let handle = spawn_helper_process(
///     Some(PathBuf::from("/usr/local/bin/dhcp-event.sh")),
///     &None,
///     Duration::from_secs(60),
/// )?;
///
/// // Lua-only mode (requires 'lua' feature)
/// # #[cfg(feature = "lua")]
/// let handle = spawn_helper_process(
///     None,
///     &Some(PathBuf::from("/etc/dnsmasq/event.lua")),
///     Duration::from_secs(30),
/// )?;
///
/// // Both script and Lua (Lua executed first, then script)
/// # #[cfg(feature = "lua")]
/// let handle = spawn_helper_process(
///     Some(PathBuf::from("/usr/local/bin/fallback.sh")),
///     &Some(PathBuf::from("/etc/dnsmasq/primary.lua")),
///     Duration::from_secs(60),
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// # Implementation Notes
///
/// - The helper task runs forever until all `HelperHandle` clones are dropped
/// - Scripts are executed sequentially to match C's behavior (one script at a time)
/// - Script stdout/stderr is captured and logged via tracing
/// - Lua functions are called synchronously (blocking the helper task)
/// - The task yields between events to prevent starvation
pub fn spawn_helper_process(
    script_path: Option<PathBuf>,
    #[allow(unused_variables)] lua_script_path: &Option<PathBuf>,
    script_timeout: Duration,
) -> Result<HelperHandle, HelperError> {
    let (sender, mut receiver) = mpsc::unbounded_channel::<ScriptEvent>();

    #[cfg(feature = "lua")]
    let lua = if let Some(lua_path) = lua_script_path.as_ref() {
        info!("Loading Lua script: {}", lua_path.display());
        let lua = Lua::new();

        // Load Lua script file
        lua.load(&std::fs::read_to_string(lua_path)?)
            .set_name(lua_path.to_string_lossy().as_ref())
            .exec()
            .map_err(|e| HelperError::LuaError(e.to_string()))?;

        // Verify lease() function exists
        let lease_fn: Result<mlua::Function, _> = lua.globals().get("lease");
        if lease_fn.is_err() {
            return Err(HelperError::LuaError(
                "lease() function missing in Lua script".to_string(),
            ));
        }

        // Call init() function if it exists
        if let Ok(init_fn) = lua.globals().get::<mlua::Function>("init") {
            init_fn
                .call::<()>(())
                .map_err(|e| HelperError::LuaError(format!("init() function failed: {e}")))?;
        }

        info!("Lua script loaded successfully");
        Some(lua)
    } else {
        None
    };

    tokio::spawn(async move {
        info!("Helper task started");

        while let Some(event) = receiver.recv().await {
            debug!("Processing event: {:?}", event.action());

            // Execute Lua function first if configured
            #[cfg(feature = "lua")]
            if let Some(ref lua) = lua {
                if let Err(e) = execute_lua_function(lua, &event) {
                    error!("Lua execution failed: {}", e);
                }
            }

            // Execute external script if configured
            if let Some(ref path) = script_path {
                if let Err(e) = execute_script(path, &event, script_timeout).await {
                    error!("Script execution failed: {}", e);
                }
            }
        }

        info!("Helper task shutting down");

        // Call Lua shutdown() function if it exists
        #[cfg(feature = "lua")]
        if let Some(lua) = lua {
            if let Ok(shutdown_fn) = lua.globals().get::<mlua::Function>("shutdown") {
                if let Err(e) = shutdown_fn.call::<()>(()) {
                    warn!("Lua shutdown() function failed: {}", e);
                }
            }
        }
    });

    Ok(HelperHandle { sender })
}

/// Execute external script for an event
///
/// Spawns the configured script as a subprocess with appropriate command-line arguments and
/// environment variables. Captures stdout/stderr and logs all output. Enforces script timeout
/// by killing the process if it exceeds the configured duration.
///
/// This function closely matches the script execution logic from helper.c (lines 684-868),
/// including:
/// - Command-line: `script_path action mac_or_duid ip_address hostname`
/// - Environment variables: DNSMASQ_* prefixed variables with event data
/// - Stdout/stderr capture and logging
/// - Timeout enforcement with automatic process kill
/// - Exit code checking
async fn execute_script(
    script_path: &Path,
    event: &ScriptEvent,
    timeout_duration: Duration,
) -> Result<(), HelperError> {
    // Build environment variables HashMap
    let mut env_vars = HashMap::new();
    populate_environment_variables(&mut env_vars, event);

    // Extract script name from path for argv[0]
    let script_name = script_path
        .file_name()
        .unwrap_or_else(|| OsStr::new("script"));

    // Build command with arguments: <script> <action> <mac> <ip> <hostname>
    let mut cmd = Command::new(script_path);
    cmd.arg(event.action())
        .arg(event.mac_or_duid())
        .arg(event.ip_address())
        .arg(event.hostname())
        .env_clear()
        .envs(env_vars)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    info!(
        script = %script_path.display(),
        action = event.action(),
        "Executing script"
    );

    // Spawn the script process
    let mut child = cmd.spawn().map_err(|e| HelperError::FailedToSpawnScript {
        path: script_path.to_path_buf(),
        error: e,
    })?;

    // Capture stdout and stderr for logging
    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let stdout_reader = BufReader::new(stdout);
    let stderr_reader = BufReader::new(stderr);

    // Spawn tasks to read stdout/stderr
    let stdout_task = tokio::spawn(async move {
        let mut lines = stdout_reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            info!(script_stdout = %line, "Script output");
        }
    });

    let stderr_task = tokio::spawn(async move {
        let mut lines = stderr_reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            error!(script_stderr = %line, "Script error output");
        }
    });

    // Wait for script completion with timeout
    let wait_result = time::timeout(timeout_duration, child.wait()).await;

    // Join output reading tasks
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    match wait_result {
        Ok(Ok(status)) => {
            if status.success() {
                info!(
                    script = %script_path.display(),
                    action = event.action(),
                    "Script completed successfully"
                );
                Ok(())
            } else {
                let code = status.code().unwrap_or(-1);
                error!(
                    script = %script_path.display(),
                    exit_code = code,
                    "Script exited with error"
                );
                Err(HelperError::ScriptNonZeroExit { code })
            }
        }
        Ok(Err(e)) => {
            error!(
                script = %script_path.display(),
                error = %e,
                "Failed to wait for script"
            );
            Err(HelperError::IoError(e))
        }
        Err(_) => {
            // Timeout occurred, kill the script
            error!(
                script = %script_path.display(),
                timeout = ?timeout_duration,
                "Script timed out, killing process"
            );
            let _ = child.kill().await;
            Err(HelperError::ScriptTimeout {
                duration: timeout_duration,
            })
        }
    }
}

/// Populate environment variables for script execution
///
/// Translates event data into `DNSMASQ_*` environment variables matching the exact format from
/// `helper.c` (lines 764-846). Sets variables to empty string or omits them based on whether
/// data is present, ensuring backward compatibility with existing scripts.
///
/// Environment variables set:
/// - `DNSMASQ_LEASE_ACTION`: Event action string
/// - `DNSMASQ_CLIENT_ID`: DHCP client identifier (`DHCPv4` only)
/// - `DNSMASQ_INTERFACE`: Network interface name
/// - `DNSMASQ_LEASE_EXPIRES`: Lease expiry timestamp
/// - `DNSMASQ_DOMAIN`: Domain name portion of hostname
/// - `DNSMASQ_VENDOR_CLASS`: Vendor class identifier
/// - `DNSMASQ_SUPPLIED_HOSTNAME`: Hostname from DHCP `option 12`
/// - `DNSMASQ_CIRCUIT_ID`: Relay agent circuit ID
/// - `DNSMASQ_SUBSCRIBER_ID`: Relay agent subscriber ID
/// - `DNSMASQ_REMOTE_ID`: Relay agent remote ID
/// - `DNSMASQ_RELAY_ADDRESS`: Relay agent IP address
/// - `DNSMASQ_TAGS`: Space-separated tag list
/// - `DNSMASQ_TIME_REMAINING`: Seconds until lease expires
/// - `DNSMASQ_OLD_HOSTNAME`: Previous hostname (for `ACTION_OLD_HOSTNAME`)
/// - `DNSMASQ_USER_CLASS0`, `DNSMASQ_USER_CLASS1`, ...: User class options
///
/// For TFTP events:
/// - `DNSMASQ_FILE_SIZE`: Size of transferred file
///
/// Note: Empty options are omitted rather than set to empty strings, matching C behavior.
fn populate_environment_variables(env: &mut HashMap<String, String>, event: &ScriptEvent) {
    // Set action type
    env.insert(
        "DNSMASQ_LEASE_ACTION".to_string(),
        event.action().to_string(),
    );

    match event {
        ScriptEvent::DhcpLease {
            interface,
            expiry,
            client_id,
            hostname,
            vendor_class,
            supplied_hostname,
            circuit_id,
            remote_id,
            subscriber_id,
            relay_address,
            tags,
            user_classes,
            time_remaining,
            old_hostname,
            ..
        } => {
            if !interface.is_empty() {
                env.insert("DNSMASQ_INTERFACE".to_string(), interface.clone());
            }
            env.insert("DNSMASQ_LEASE_EXPIRES".to_string(), expiry.to_string());

            if let Some(cid) = client_id {
                env.insert("DNSMASQ_CLIENT_ID".to_string(), cid.clone());
            }

            // Split hostname into hostname and domain
            if let Some(dot_pos) = hostname.find('.') {
                env.insert(
                    "DNSMASQ_DOMAIN".to_string(),
                    hostname[dot_pos + 1..].to_string(),
                );
            }

            if let Some(vc) = vendor_class {
                env.insert("DNSMASQ_VENDOR_CLASS".to_string(), vc.clone());
            }

            if let Some(sh) = supplied_hostname {
                env.insert("DNSMASQ_SUPPLIED_HOSTNAME".to_string(), sh.clone());
            }

            if let Some(cid) = circuit_id {
                env.insert("DNSMASQ_CIRCUIT_ID".to_string(), cid.clone());
            }

            if let Some(rid) = remote_id {
                env.insert("DNSMASQ_REMOTE_ID".to_string(), rid.clone());
            }

            if let Some(sid) = subscriber_id {
                env.insert("DNSMASQ_SUBSCRIBER_ID".to_string(), sid.clone());
            }

            if let Some(ra) = relay_address {
                env.insert("DNSMASQ_RELAY_ADDRESS".to_string(), ra.clone());
            }

            if !tags.is_empty() {
                env.insert("DNSMASQ_TAGS".to_string(), tags.join(" "));
            }

            if *time_remaining > 0 {
                env.insert(
                    "DNSMASQ_TIME_REMAINING".to_string(),
                    time_remaining.to_string(),
                );
            }

            if let Some(old_host) = old_hostname {
                env.insert("DNSMASQ_OLD_HOSTNAME".to_string(), old_host.clone());
            }

            // User classes
            for (i, user_class) in user_classes.iter().enumerate() {
                env.insert(format!("DNSMASQ_USER_CLASS{i}"), user_class.clone());
            }
        }

        ScriptEvent::DhcpLeaseOld {
            interface,
            expiry,
            client_id,
            ..
        } => {
            if !interface.is_empty() {
                env.insert("DNSMASQ_INTERFACE".to_string(), interface.clone());
            }
            env.insert("DNSMASQ_LEASE_EXPIRES".to_string(), expiry.to_string());

            if let Some(cid) = client_id {
                env.insert("DNSMASQ_CLIENT_ID".to_string(), cid.clone());
            }
        }

        ScriptEvent::DhcpLeaseDel { interface, .. } 
        | ScriptEvent::ArpAdd { interface, .. } 
        | ScriptEvent::ArpDel { interface, .. } 
        | ScriptEvent::RelaySnoop { interface, .. } => {
            if !interface.is_empty() {
                env.insert("DNSMASQ_INTERFACE".to_string(), interface.clone());
            }
        }

        ScriptEvent::TftpTransfer {
            file_size,
            interface,
            ..
        } => {
            env.insert("DNSMASQ_FILE_SIZE".to_string(), file_size.to_string());
            if !interface.is_empty() {
                env.insert("DNSMASQ_INTERFACE".to_string(), interface.clone());
            }
        }
    }
}

/// Execute Lua function for an event
///
/// Calls the appropriate Lua function based on event type:
/// - `lease(action, data)` for DHCP events
/// - `tftp(action, data)` for TFTP events
/// - `arp(action, data)` for ARP events
/// - `snoop(action, data)` for relay snooping
///
/// The data table contains event fields matching the environment variables but in Lua table
/// format. This matches the Lua integration from helper.c (lines 501-677).
#[cfg(feature = "lua")]
fn execute_lua_function(lua: &Lua, event: &ScriptEvent) -> Result<(), HelperError> {
    let action = event.action();

    let function_name = match event {
        ScriptEvent::DhcpLease { .. }
        | ScriptEvent::DhcpLeaseOld { .. }
        | ScriptEvent::DhcpLeaseDel { .. } => "lease",
        ScriptEvent::TftpTransfer { .. } => "tftp",
        ScriptEvent::ArpAdd { .. } | ScriptEvent::ArpDel { .. } => "arp",
        ScriptEvent::RelaySnoop { .. } => "snoop",
    };

    // Get the Lua function (may not exist for optional functions like tftp, arp, snoop)
    let lua_fn: mlua::Function = if let Ok(f) = lua.globals().get(function_name) {
        f
    } else {
        debug!("Lua function '{}' not found, skipping", function_name);
        return Ok(());
    };

    // Create data table
    let data_table = lua
        .create_table()
        .map_err(|e| HelperError::LuaError(e.to_string()))?;

    // Populate table based on event type
    match event {
        ScriptEvent::DhcpLease {
            mac,
            ip,
            hostname,
            interface,
            expiry,
            client_id,
            vendor_class,
            supplied_hostname,
            circuit_id,
            remote_id,
            subscriber_id,
            relay_address,
            tags,
            user_classes,
            time_remaining,
            old_hostname,
            ..
        } => {
            data_table
                .set("mac_address", mac.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
            data_table
                .set("ip_address", ip.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
            data_table
                .set("hostname", hostname.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
            data_table
                .set("interface", interface.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
            data_table
                .set("lease_expires", *expiry)
                .map_err(|e| HelperError::LuaError(e.to_string()))?;

            if let Some(cid) = client_id {
                data_table
                    .set("client_id", cid.clone())
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }
            if let Some(vc) = vendor_class {
                data_table
                    .set("vendor_class", vc.clone())
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }
            if let Some(sh) = supplied_hostname {
                data_table
                    .set("supplied_hostname", sh.clone())
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }
            if let Some(cid) = circuit_id {
                data_table
                    .set("circuit_id", cid.clone())
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }
            if let Some(rid) = remote_id {
                data_table
                    .set("remote_id", rid.clone())
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }
            if let Some(sid) = subscriber_id {
                data_table
                    .set("subscriber_id", sid.clone())
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }
            if let Some(ra) = relay_address {
                data_table
                    .set("relay_address", ra.clone())
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }
            if !tags.is_empty() {
                data_table
                    .set("tags", tags.join(" "))
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }
            if *time_remaining > 0 {
                data_table
                    .set("time_remaining", *time_remaining)
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }
            if let Some(old_host) = old_hostname {
                data_table
                    .set("old_hostname", old_host.clone())
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }

            // User classes
            for (i, user_class) in user_classes.iter().enumerate() {
                data_table
                    .set(format!("user_class{i}"), user_class.clone())
                    .map_err(|e| HelperError::LuaError(e.to_string()))?;
            }
        }

        ScriptEvent::TftpTransfer {
            file_size,
            destination,
            filename,
            ..
        } => {
            data_table
                .set("file_size", file_size.to_string())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
            data_table
                .set("destination_address", destination.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
            data_table
                .set("file_name", filename.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
        }

        ScriptEvent::ArpAdd { mac, ip, .. } | ScriptEvent::ArpDel { mac, ip, .. } => {
            data_table
                .set("mac_address", mac.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
            data_table
                .set("client_address", ip.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
        }

        ScriptEvent::RelaySnoop {
            client_address,
            prefix,
            interface,
        } => {
            data_table
                .set("client_address", client_address.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
            data_table
                .set("prefix", prefix.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
            data_table
                .set("client_interface", interface.clone())
                .map_err(|e| HelperError::LuaError(e.to_string()))?;
        }

        _ => {}
    }

    // Call Lua function: function_name(action, data_table)
    info!(
        lua_function = function_name,
        action = action,
        "Calling Lua function"
    );

    lua_fn
        .call::<()>((action, data_table))
        .map_err(|e| HelperError::LuaError(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_event_action() {
        let event = ScriptEvent::DhcpLease {
            mac: "00:11:22:33:44:55".to_string(),
            ip: "192.168.1.100".to_string(),
            hostname: "test".to_string(),
            interface: "eth0".to_string(),
            expiry: 0,
            client_id: None,
            tags: Box::new(vec![]),
            vendor_class: None,
            supplied_hostname: None,
            circuit_id: None,
            remote_id: None,
            subscriber_id: None,
            relay_address: None,
            user_classes: Box::new(vec![]),
            time_remaining: 0,
            old_hostname: None,
        };

        assert_eq!(event.action(), "add");
        assert_eq!(event.mac_or_duid(), "00:11:22:33:44:55");
        assert_eq!(event.ip_address(), "192.168.1.100");
        assert_eq!(event.hostname(), "test");
    }

    #[test]
    fn test_environment_variables() {
        let event = ScriptEvent::DhcpLease {
            mac: "00:11:22:33:44:55".to_string(),
            ip: "192.168.1.100".to_string(),
            hostname: "test.example.com".to_string(),
            interface: "eth0".to_string(),
            expiry: 1_234_567_890,
            client_id: Some("client-id-hex".to_string()),
            tags: Box::new(vec!["tag1".to_string(), "tag2".to_string()]),
            vendor_class: Some("vendor".to_string()),
            supplied_hostname: Some("supplied".to_string()),
            circuit_id: Some("circuit".to_string()),
            remote_id: Some("remote".to_string()),
            subscriber_id: Some("subscriber".to_string()),
            relay_address: Some("192.168.1.1".to_string()),
            user_classes: Box::new(vec!["class0".to_string(), "class1".to_string()]),
            time_remaining: 3600,
            old_hostname: None,
        };

        let mut env = HashMap::new();
        populate_environment_variables(&mut env, &event);

        assert_eq!(env.get("DNSMASQ_LEASE_ACTION"), Some(&"add".to_string()));
        assert_eq!(env.get("DNSMASQ_INTERFACE"), Some(&"eth0".to_string()));
        assert_eq!(
            env.get("DNSMASQ_CLIENT_ID"),
            Some(&"client-id-hex".to_string())
        );
        assert_eq!(env.get("DNSMASQ_DOMAIN"), Some(&"example.com".to_string()));
        assert_eq!(env.get("DNSMASQ_TAGS"), Some(&"tag1 tag2".to_string()));
        assert_eq!(env.get("DNSMASQ_USER_CLASS0"), Some(&"class0".to_string()));
        assert_eq!(env.get("DNSMASQ_USER_CLASS1"), Some(&"class1".to_string()));
    }

    #[tokio::test]
    async fn test_helper_handle_close() {
        let handle = spawn_helper_process(None, &None, DEFAULT_SCRIPT_TIMEOUT).unwrap();

        assert!(!handle.is_closed());
        handle.close();

        // After close, handle should be closed
        // Note: The actual closure is asynchronous, so we can't directly test is_closed()
        // in this synchronous context without waiting
    }
}
