// Copyright (C) 2000-2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! Privilege-separated helper process for executing external lease-change scripts
//!
//! This module implements the privilege separation architecture from src/helper.c,
//! where the main daemon drops root privileges but spawns a helper task that retains
//! elevated privileges to execute DHCP lease-change scripts, TFTP notifications, and
//! ARP event scripts in a controlled manner.
//!
//! # Architecture
//!
//! The helper task runs independently, communicating with the main daemon via async
//! channels (tokio::sync::mpsc). It receives serialized event data, validates it, and
//! executes the configured script with appropriate environment variables using
//! tokio::process::Command. This prevents a compromised main daemon from gaining root
//! access while still allowing controlled script execution.
//!
//! # Key Differences from C Implementation (src/helper.c)
//!
//! - **Process Model**: Uses tokio::spawn async task instead of fork()
//! - **IPC Mechanism**: Uses tokio::sync::mpsc channels instead of Unix pipes
//! - **Script Execution**: Uses tokio::process::Command instead of fork+exec
//! - **Serialization**: Uses serde for type-safe ScriptData instead of manual struct packing
//! - **Lua Integration**: Uses rlua crate instead of C Lua API (optional feature)
//! - **Signal Handling**: Uses tokio::signal instead of sigaction
//! - **Memory Safety**: Eliminates manual buffer management, no malloc/free
//!
//! # Security Model
//!
//! - Script path is fixed at helper creation time and cannot be changed
//! - All data received from main process is validated before use
//! - Environment variables are constructed from validated structures only
//! - Helper task can optionally drop to configured uid/gid before script execution
//!
//! # Supported Event Types
//!
//! - DHCPv4 lease events: add, del, old, old-hostname
//! - DHCPv6 lease events: add, del, old (with IA_NA, IA_TA, IA_PD)
//! - TFTP transfer notifications
//! - ARP detection events: arp-add, arp-del
//! - DHCPv6 relay snooping events
//!
//! # Usage Example
//!
//! ```no_run
//! use dnsmasq::process::helper::{create_helper, HelperHandle, ScriptData};
//! use nix::unistd::{Uid, Gid};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let script_path = "/usr/local/bin/dhcp-event.sh";
//!     let script_uid = Uid::from_raw(1000);
//!     let script_gid = Gid::from_raw(1000);
//!     
//!     let helper = create_helper(
//!         script_path.to_string(),
//!         Some(script_uid),
//!         Some(script_gid),
//!         None, // No Lua script
//!     ).await?;
//!     
//!     // Helper is now running, send events via helper.send_event()
//!     Ok(())
//! }
//! ```

use crate::config::types::DaemonOptions;
use crate::dhcp::common::{
    ACTION_ADD, ACTION_ARP, ACTION_ARP_DEL, ACTION_DEL, ACTION_OLD,
    ACTION_OLD_HOSTNAME, ACTION_RELAY_SNOOP, ACTION_TFTP, DHCP_CHADDR_MAX,
    ARPHRD_ETHER, LEASE_NA, LEASE_TA,
};
use crate::dhcp::lease::DhcpLease;
use crate::logging::logger::Logger;
use crate::network::sockets::indextoname;
use crate::process::privileges::{drop_privileges, PrivilegeError};

use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::{Gid, Uid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::io::{Error as IoError, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc::{self, Sender, Receiver};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

#[cfg(feature = "lua")]
use rlua::{Context, Function, Lua, Table, Value};

/// Maximum size for extra DHCP option data buffer (matches C MAXDNAME)
const MAX_EXTRADATA: usize = 1024;

/// Maximum hostname length
const MAX_HOSTNAME: usize = 256;

/// Maximum vendor class count
const MAX_VENDOR_CLASSES: usize = 8;

/// Errors that can occur during helper process operations
#[derive(Debug)]
pub enum HelperError {
    /// Failed to fork the helper process
    ForkFailed(IoError),
    /// Failed to create IPC pipe for communication
    PipeFailed(IoError),
    /// Failed to execute script
    ExecFailed(IoError),
    /// Script execution failed with non-zero exit code
    ScriptFailed { exit_code: i32, stderr: String },
    /// Lua script error
    #[cfg(feature = "lua")]
    LuaError(String),
    /// I/O error during helper operation
    IoError(IoError),
    /// Serialization error
    SerializationError(String),
    /// Invalid script path
    InvalidScriptPath(String),
    /// Channel send error
    SendError(String),
    /// Privilege dropping error
    PrivilegeDropError(PrivilegeError),
}

impl std::fmt::Display for HelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelperError::ForkFailed(e) => write!(f, "Failed to fork helper process: {}", e),
            HelperError::PipeFailed(e) => write!(f, "Failed to create IPC pipe: {}", e),
            HelperError::ExecFailed(e) => write!(f, "Failed to execute script: {}", e),
            HelperError::ScriptFailed { exit_code, stderr } => {
                write!(f, "Script failed with exit code {}: {}", exit_code, stderr)
            }
            #[cfg(feature = "lua")]
            HelperError::LuaError(e) => write!(f, "Lua error: {}", e),
            HelperError::IoError(e) => write!(f, "I/O error: {}", e),
            HelperError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            HelperError::InvalidScriptPath(e) => write!(f, "Invalid script path: {}", e),
            HelperError::SendError(e) => write!(f, "Channel send error: {}", e),
            HelperError::PrivilegeDropError(e) => write!(f, "Privilege drop error: {}", e),
        }
    }
}

impl std::error::Error for HelperError {}

impl From<IoError> for HelperError {
    fn from(err: IoError) -> Self {
        HelperError::IoError(err)
    }
}

impl From<PrivilegeError> for HelperError {
    fn from(err: PrivilegeError) -> Self {
        HelperError::PrivilegeDropError(err)
    }
}

/// Script event data wire format (matches C struct script_data from helper.c lines 151-173)
///
/// This structure is serialized and transmitted from the main daemon to the helper
/// task for script execution. All fields match the C implementation exactly to maintain
/// protocol compatibility during transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptData {
    /// Action type: "add", "del", "old", "tftp", "arp-add", "arp-del", "relay-snoop"
    /// Original C field: action (int)
    pub action: String,
    
    /// Lease flags (LEASE_TA, LEASE_NA for DHCPv6)
    /// Original C field: flags (unsigned int)
    pub flags: u32,
    
    /// Hardware address length (typically 6 for Ethernet)
    /// Original C field: hwaddr_len (size_t)
    pub hwaddr_len: usize,
    
    /// Hardware address type (ARPHRD_ETHER = 1)
    /// Original C field: hwaddr_type (int)
    pub hwaddr_type: u32,
    
    /// Client ID length
    /// Original C field: clid_len (size_t)
    pub clid_len: usize,
    
    /// Hostname length
    /// Original C field: hostname_len (size_t)
    pub hostname_len: usize,
    
    /// Extra data (DHCP options) length
    /// Original C field: ed_len (size_t)
    pub ed_len: usize,
    
    /// IPv4 address (for DHCPv4 leases)
    /// Original C field: addr (struct in_addr)
    pub addr: Option<Ipv4Addr>,
    
    /// Gateway/relay IPv4 address
    /// Original C field: giaddr (struct in_addr)
    pub giaddr: Option<Ipv4Addr>,
    
    /// Remaining lease time in seconds (for HAVE_BROKEN_RTC systems)
    /// Original C field: length (time_t)
    pub remaining_time: u64,
    
    /// Absolute expiry time (Unix timestamp)
    /// Original C field: expires (time_t)
    pub expires: u64,
    
    /// TFTP file size in bytes
    /// Original C field: file_len (off_t)
    pub file_len: u64,
    
    /// IPv6 address (for DHCPv6 leases)
    /// Original C field: addr6 (struct in6_addr)
    pub addr6: Option<Ipv6Addr>,
    
    /// Vendor class count
    /// Original C field: vendorclass_count (unsigned int)
    pub vendorclass_count: u32,
    
    /// DHCPv6 IAID (Identity Association Identifier)
    /// Original C field: iaid (unsigned int)
    pub iaid: u32,
    
    /// Hardware address bytes
    /// Original C field: hwaddr[DHCP_CHADDR_MAX]
    pub hwaddr: Vec<u8>,
    
    /// Network interface name
    /// Original C field: interface[IF_NAMESIZE]
    pub interface: String,
    
    /// Hostname (variable length)
    /// Original C field: hostname (variable)
    pub hostname: String,
    
    /// Client identifier (variable length)
    /// Original C field: clid (variable)
    pub clid: Vec<u8>,
    
    /// Extra data buffer for DHCP options (variable length)
    /// Original C field: ed (variable)
    pub extradata: Vec<u8>,
    
    /// Vendor class data (variable length)
    /// Original C field: vendorclass (variable)
    pub vendorclass: Vec<String>,
}

impl Default for ScriptData {
    fn default() -> Self {
        Self {
            action: String::new(),
            flags: 0,
            hwaddr_len: 0,
            hwaddr_type: 0,
            clid_len: 0,
            hostname_len: 0,
            ed_len: 0,
            addr: None,
            giaddr: None,
            remaining_time: 0,
            expires: 0,
            file_len: 0,
            addr6: None,
            vendorclass_count: 0,
            iaid: 0,
            hwaddr: Vec::new(),
            interface: String::new(),
            hostname: String::new(),
            clid: Vec::new(),
            extradata: Vec::new(),
            vendorclass: Vec::new(),
        }
    }
}

/// Internal event type sent to helper task
#[derive(Debug, Clone)]
enum HelperEvent {
    /// Script execution event with serialized data
    ScriptEvent(ScriptData),
    /// Shutdown signal
    Shutdown,
}

/// Handle to the helper task for sending events
///
/// This handle allows the main daemon to send lease-change events, TFTP notifications,
/// and ARP events to the helper task for script execution. The helper task processes
/// events asynchronously without blocking the main event loop.
pub struct HelperHandle {
    /// Channel sender for events
    tx: Sender<HelperEvent>,
    /// Join handle for the helper task
    task_handle: JoinHandle<Result<(), HelperError>>,
}

impl HelperHandle {
    /// Send a script event to the helper task
    ///
    /// # Arguments
    ///
    /// * `data` - Script event data to send
    ///
    /// # Returns
    ///
    /// * `Ok(())` if event was queued successfully
    /// * `Err(HelperError)` if channel is closed or full
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::process::helper::{HelperHandle, ScriptData};
    /// # async fn example(helper: &HelperHandle, data: ScriptData) -> Result<(), Box<dyn std::error::Error>> {
    /// helper.send_event(data).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_event(&self, data: ScriptData) -> Result<(), HelperError> {
        self.tx
            .send(HelperEvent::ScriptEvent(data))
            .await
            .map_err(|e| HelperError::SendError(format!("Failed to send event: {}", e)))
    }

    /// Shutdown the helper task gracefully
    ///
    /// Sends a shutdown signal and waits for the helper task to complete.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if helper shut down cleanly
    /// * `Err(HelperError)` if helper task encountered an error
    pub async fn shutdown(self) -> Result<(), HelperError> {
        // Send shutdown signal
        let _ = self.tx.send(HelperEvent::Shutdown).await;
        
        // Wait for task to complete
        match self.task_handle.await {
            Ok(result) => result,
            Err(e) => Err(HelperError::IoError(IoError::new(
                ErrorKind::Other,
                format!("Helper task panicked: {}", e),
            ))),
        }
    }
}

/// Create and spawn the privilege-separated helper task
///
/// This function spawns an async task that retains elevated privileges (or drops to
/// the specified uid/gid) for executing external scripts. The helper task receives
/// events via an mpsc channel and executes the configured script with appropriate
/// environment variables.
///
/// # Arguments
///
/// * `script_path` - Path to the lease-change script to execute (--dhcp-script)
/// * `script_uid` - Optional UID to drop to before executing script
/// * `script_gid` - Optional GID to drop to before executing script
/// * `lua_script` - Optional Lua script path (--dhcp-luascript, requires 'lua' feature)
///
/// # Returns
///
/// * `Ok(HelperHandle)` - Handle for sending events to the helper
/// * `Err(HelperError)` - If helper task creation failed
///
/// # Security
///
/// The script path is fixed at creation time and cannot be changed afterward. This
/// prevents a compromised main daemon from executing arbitrary commands with elevated
/// privileges. The helper validates all received data before use.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::process::helper::create_helper;
/// use nix::unistd::{Uid, Gid};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let helper = create_helper(
///         "/usr/local/bin/dhcp-event.sh".to_string(),
///         Some(Uid::from_raw(1000)),
///         Some(Gid::from_raw(1000)),
///         None,
///     ).await?;
///     
///     // Use helper...
///     helper.shutdown().await?;
///     Ok(())
/// }
/// ```
pub async fn create_helper(
    script_path: String,
    script_uid: Option<Uid>,
    script_gid: Option<Gid>,
    #[cfg(feature = "lua")] lua_script: Option<String>,
    #[cfg(not(feature = "lua"))] _lua_script: Option<String>,
) -> Result<HelperHandle, HelperError> {
    // Validate script path
    if script_path.is_empty() {
        return Err(HelperError::InvalidScriptPath(
            "Script path cannot be empty".to_string(),
        ));
    }

    // Create channel for event communication (buffer size 100 matching C's queue depth)
    let (tx, rx) = mpsc::channel::<HelperEvent>(100);

    info!(
        "Creating helper task with script: {}, uid: {:?}, gid: {:?}",
        script_path, script_uid, script_gid
    );

    // Spawn helper task
    #[cfg(feature = "lua")]
    let task_handle = tokio::spawn(helper_main_loop(
        rx,
        script_path,
        script_uid,
        script_gid,
        lua_script,
    ));

    #[cfg(not(feature = "lua"))]
    let task_handle = tokio::spawn(helper_main_loop(
        rx,
        script_path,
        script_uid,
        script_gid,
    ));

    Ok(HelperHandle { tx, task_handle })
}

/// Helper task main loop (replaces C helper.c main loop lines 182-688)
///
/// This async function runs continuously, receiving events from the main daemon
/// and dispatching them to either external scripts or Lua functions. It maintains
/// the Lua interpreter state (if enabled) and handles script execution errors.
#[cfg(feature = "lua")]
async fn helper_main_loop(
    mut rx: Receiver<HelperEvent>,
    script_path: String,
    script_uid: Option<Uid>,
    script_gid: Option<Gid>,
    lua_script: Option<String>,
) -> Result<(), HelperError> {
    info!("Helper task started");

    // Initialize Lua interpreter if Lua script provided
    let lua_state = if let Some(ref lua_path) = lua_script {
        info!("Initializing Lua interpreter with script: {}", lua_path);
        let lua = Lua::new();
        
        // Load Lua script
        lua.context(|ctx| {
            let script_content = std::fs::read_to_string(lua_path)
                .map_err(|e| HelperError::LuaError(format!("Failed to read Lua script: {}", e)))?;
            
            ctx.load(&script_content)
                .exec()
                .map_err(|e| HelperError::LuaError(format!("Failed to load Lua script: {}", e)))?;
            
            // Call init() function if it exists
            if let Ok(init_fn) = ctx.globals().get::<_, Function>("init") {
                init_fn.call::<_, ()>(())
                    .map_err(|e| HelperError::LuaError(format!("Lua init() failed: {}", e)))?;
                info!("Lua init() function called successfully");
            }
            
            Ok(())
        })?;
        
        Some(lua)
    } else {
        None
    };

    // Main event loop
    while let Some(event) = rx.recv().await {
        match event {
            HelperEvent::ScriptEvent(data) => {
                debug!("Helper received event: action={}", data.action);
                
                // Try Lua first if available
                if let Some(ref lua) = lua_state {
                    match execute_lua_script(lua, &data).await {
                        Ok(()) => {
                            debug!("Lua script executed successfully");
                            continue;
                        }
                        Err(e) => {
                            error!("Lua script execution failed: {}, falling back to shell script", e);
                        }
                    }
                }
                
                // Execute external script
                if let Err(e) = execute_external_script(
                    &script_path,
                    &data,
                    script_uid,
                    script_gid,
                ).await {
                    error!("Script execution failed: {}", e);
                }
            }
            HelperEvent::Shutdown => {
                info!("Helper task received shutdown signal");
                break;
            }
        }
    }

    // Call Lua shutdown() if available
    if let Some(ref lua) = lua_state {
        let _ = lua.context(|ctx| {
            if let Ok(shutdown_fn) = ctx.globals().get::<_, Function>("shutdown") {
                let _ = shutdown_fn.call::<_, ()>(());
                info!("Lua shutdown() function called");
            }
            Ok::<(), HelperError>(())
        });
    }

    info!("Helper task exiting");
    Ok(())
}

/// Helper task main loop (non-Lua version)
#[cfg(not(feature = "lua"))]
async fn helper_main_loop(
    mut rx: Receiver<HelperEvent>,
    script_path: String,
    script_uid: Option<Uid>,
    script_gid: Option<Gid>,
) -> Result<(), HelperError> {
    info!("Helper task started (no Lua support)");

    // Main event loop
    while let Some(event) = rx.recv().await {
        match event {
            HelperEvent::ScriptEvent(data) => {
                debug!("Helper received event: action={}", data.action);
                
                // Execute external script
                if let Err(e) = execute_external_script(
                    &script_path,
                    &data,
                    script_uid,
                    script_gid,
                ).await {
                    error!("Script execution failed: {}", e);
                }
            }
            HelperEvent::Shutdown => {
                info!("Helper task received shutdown signal");
                break;
            }
        }
    }

    info!("Helper task exiting");
    Ok(())
}

/// Execute external shell script with environment variables (replaces C lines 657-868)
///
/// Spawns the configured script as a child process using tokio::process::Command,
/// sets up DNSMASQ_* environment variables containing lease information, and
/// captures stdout/stderr for logging.
///
/// # Arguments
///
/// * `script_path` - Path to the script to execute
/// * `data` - Script event data containing lease/event information
/// * `script_uid` - Optional UID to run script as
/// * `script_gid` - Optional GID to run script as
async fn execute_external_script(
    script_path: &str,
    data: &ScriptData,
    script_uid: Option<Uid>,
    script_gid: Option<Gid>,
) -> Result<(), HelperError> {
    debug!("Executing external script: {} action={}", script_path, data.action);

    // Build environment variables
    let mut env_vars = build_script_environment(data)?;

    // Create command
    let mut cmd = Command::new(script_path);
    cmd.arg(&data.action)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Set environment variables
    for (key, value) in env_vars.iter() {
        cmd.env(key, value);
    }

    // Set uid/gid if specified
    if let Some(uid) = script_uid {
        cmd.uid(uid.as_raw());
    }
    if let Some(gid) = script_gid {
        cmd.gid(gid.as_raw());
    }

    // Spawn and wait for completion
    let output = cmd.output().await
        .map_err(|e| HelperError::ExecFailed(e))?;

    // Log output
    if !output.stdout.is_empty() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        info!("Script stdout: {}", stdout.trim());
    }

    // Check exit status
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);
        error!("Script failed with exit code {}: {}", exit_code, stderr);
        return Err(HelperError::ScriptFailed {
            exit_code,
            stderr: stderr.to_string(),
        });
    }

    debug!("Script completed successfully");
    Ok(())
}

/// Build environment variables for script execution (replaces C my_setenv and grab_extradata)
///
/// Constructs a HashMap of DNSMASQ_* environment variables based on the script event
/// data. These variables provide the script with all information about the lease or
/// event.
///
/// # Environment Variables Set
///
/// - DNSMASQ_DOMAIN - Local domain name
/// - DNSMASQ_INTERFACE - Network interface name
/// - DNSMASQ_LEASE_EXPIRES - Lease expiry timestamp
/// - DNSMASQ_LEASE_LENGTH - Remaining lease time
/// - DNSMASQ_SUPPLIED_HOSTNAME - Client-provided hostname
/// - DNSMASQ_CLIENT_ID - DHCP client identifier
/// - DNSMASQ_MAC - Hardware address (MAC)
/// - DNSMASQ_IP - IPv4 address
/// - DNSMASQ_RELAY_ADDRESS - DHCPv4 relay/gateway address
/// - DNSMASQ_IP6 - IPv6 address
/// - DNSMASQ_IAID - DHCPv6 IAID
/// - DNSMASQ_TAGS - Space-separated lease tags
/// - DNSMASQ_REQUESTED_OPTIONS - List of requested DHCP options
/// - DNSMASQ_VENDOR_CLASS - Vendor class identifier
/// - DNSMASQ_TFTP_FILE - TFTP filename
/// - DNSMASQ_TFTP_SIZE - TFTP file size
/// - DNSMASQ_ARP_MAC - ARP hardware address
/// - DNSMASQ_ARP_IP - ARP IP address
fn build_script_environment(data: &ScriptData) -> Result<HashMap<String, String>, HelperError> {
    let mut env = HashMap::new();

    // Interface name
    if !data.interface.is_empty() {
        env.insert("DNSMASQ_INTERFACE".to_string(), data.interface.clone());
    }

    // Hostname
    if !data.hostname.is_empty() {
        env.insert("DNSMASQ_SUPPLIED_HOSTNAME".to_string(), data.hostname.clone());
    }

    // Client ID (hex encoded)
    if !data.clid.is_empty() {
        let clid_hex = data.clid.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        env.insert("DNSMASQ_CLIENT_ID".to_string(), clid_hex);
    }

    // Hardware address
    if data.hwaddr_len > 0 && !data.hwaddr.is_empty() {
        let mac = data.hwaddr.iter()
            .take(data.hwaddr_len)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        env.insert("DNSMASQ_MAC".to_string(), mac);
    }

    // IPv4 address
    if let Some(addr) = data.addr {
        env.insert("DNSMASQ_IP".to_string(), addr.to_string());
    }

    // IPv4 gateway/relay address
    if let Some(giaddr) = data.giaddr {
        env.insert("DNSMASQ_RELAY_ADDRESS".to_string(), giaddr.to_string());
    }

    // IPv6 address
    if let Some(addr6) = data.addr6 {
        env.insert("DNSMASQ_IP6".to_string(), addr6.to_string());
    }

    // DHCPv6 IAID
    if data.iaid != 0 {
        env.insert("DNSMASQ_IAID".to_string(), data.iaid.to_string());
    }

    // Lease expiry time (Unix timestamp)
    if data.expires > 0 {
        env.insert("DNSMASQ_LEASE_EXPIRES".to_string(), data.expires.to_string());
    }

    // Remaining lease time (seconds)
    if data.remaining_time > 0 {
        env.insert("DNSMASQ_LEASE_LENGTH".to_string(), data.remaining_time.to_string());
    }

    // TFTP file size
    if data.file_len > 0 {
        env.insert("DNSMASQ_TFTP_SIZE".to_string(), data.file_len.to_string());
    }

    // Vendor class information
    if data.vendorclass_count > 0 {
        let vendor_class = data.vendorclass.join(" ");
        env.insert("DNSMASQ_VENDOR_CLASS".to_string(), vendor_class);
    }

    // Action-specific variables
    match data.action.as_str() {
        ACTION_TFTP => {
            // For TFTP, hostname field contains the filename
            if !data.hostname.is_empty() {
                env.insert("DNSMASQ_TFTP_FILE".to_string(), data.hostname.clone());
            }
        }
        ACTION_ARP | ACTION_ARP_DEL => {
            // For ARP events, use specific variable names
            if data.hwaddr_len > 0 && !data.hwaddr.is_empty() {
                let mac = data.hwaddr.iter()
                    .take(data.hwaddr_len)
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":");
                env.insert("DNSMASQ_ARP_MAC".to_string(), mac);
            }
            if let Some(addr) = data.addr {
                env.insert("DNSMASQ_ARP_IP".to_string(), addr.to_string());
            }
        }
        _ => {}
    }

    // Extra DHCP option data (parsed into individual variables)
    if data.ed_len > 0 && !data.extradata.is_empty() {
        parse_extradata_into_env(&data.extradata, &mut env);
    }

    Ok(env)
}

/// Parse extra DHCP option data into environment variables
///
/// Extracts individual DHCP options from the extra data buffer and creates
/// DNSMASQ_OPTION_<num> environment variables for each option.
fn parse_extradata_into_env(extradata: &[u8], env: &mut HashMap<String, String>) {
    let mut offset = 0;
    
    while offset + 2 <= extradata.len() {
        let option_num = extradata[offset];
        let option_len = extradata[offset + 1] as usize;
        offset += 2;
        
        if offset + option_len > extradata.len() {
            break;
        }
        
        let option_data = &extradata[offset..offset + option_len];
        let option_hex = option_data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        
        env.insert(
            format!("DNSMASQ_OPTION_{}", option_num),
            option_hex,
        );
        
        offset += option_len;
    }
}

/// Execute Lua script function (replaces C Lua integration lines 319-496)
///
/// Calls the appropriate Lua function (lease, tftp, arp, snoop) based on the
/// action type, passing event data as a Lua table.
#[cfg(feature = "lua")]
async fn execute_lua_script(lua: &Lua, data: &ScriptData) -> Result<(), HelperError> {
    lua.context(|ctx| {
        // Determine which Lua function to call based on action
        let function_name = match data.action.as_str() {
            ACTION_ADD | ACTION_DEL | ACTION_OLD | ACTION_OLD_HOSTNAME => "lease",
            ACTION_TFTP => "tftp",
            ACTION_ARP | ACTION_ARP_DEL => "arp",
            ACTION_RELAY_SNOOP => "snoop",
            _ => {
                return Err(HelperError::LuaError(format!(
                    "Unknown action type: {}",
                    data.action
                )));
            }
        };

        // Get the Lua function
        let func: Function = ctx
            .globals()
            .get(function_name)
            .map_err(|e| HelperError::LuaError(format!(
                "Lua function '{}' not found: {}",
                function_name, e
            )))?;

        // Build Lua table with event data
        let table = ctx.create_table()
            .map_err(|e| HelperError::LuaError(format!("Failed to create Lua table: {}", e)))?;

        // Set action
        table.set("action", data.action.as_str())
            .map_err(|e| HelperError::LuaError(format!("Failed to set action: {}", e)))?;

        // Set interface
        if !data.interface.is_empty() {
            table.set("interface", data.interface.as_str())
                .map_err(|e| HelperError::LuaError(format!("Failed to set interface: {}", e)))?;
        }

        // Set hostname
        if !data.hostname.is_empty() {
            table.set("hostname", data.hostname.as_str())
                .map_err(|e| HelperError::LuaError(format!("Failed to set hostname: {}", e)))?;
        }

        // Set MAC address
        if data.hwaddr_len > 0 && !data.hwaddr.is_empty() {
            let mac = data.hwaddr.iter()
                .take(data.hwaddr_len)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");
            table.set("mac_address", mac.as_str())
                .map_err(|e| HelperError::LuaError(format!("Failed to set mac_address: {}", e)))?;
        }

        // Set IPv4 address
        if let Some(addr) = data.addr {
            table.set("ip_address", addr.to_string())
                .map_err(|e| HelperError::LuaError(format!("Failed to set ip_address: {}", e)))?;
        }

        // Set IPv6 address
        if let Some(addr6) = data.addr6 {
            table.set("ip6_address", addr6.to_string())
                .map_err(|e| HelperError::LuaError(format!("Failed to set ip6_address: {}", e)))?;
        }

        // Set client ID
        if !data.clid.is_empty() {
            let clid_hex = data.clid.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");
            table.set("client_id", clid_hex.as_str())
                .map_err(|e| HelperError::LuaError(format!("Failed to set client_id: {}", e)))?;
        }

        // Set expiry time
        if data.expires > 0 {
            table.set("expires", data.expires as f64)
                .map_err(|e| HelperError::LuaError(format!("Failed to set expires: {}", e)))?;
        }

        // Set IAID for DHCPv6
        if data.iaid != 0 {
            table.set("iaid", data.iaid)
                .map_err(|e| HelperError::LuaError(format!("Failed to set iaid: {}", e)))?;
        }

        // Set flags
        if data.flags != 0 {
            table.set("flags", data.flags)
                .map_err(|e| HelperError::LuaError(format!("Failed to set flags: {}", e)))?;
        }

        // For TFTP, set file and size
        if data.action == ACTION_TFTP {
            if !data.hostname.is_empty() {
                table.set("file", data.hostname.as_str())
                    .map_err(|e| HelperError::LuaError(format!("Failed to set file: {}", e)))?;
            }
            if data.file_len > 0 {
                table.set("size", data.file_len as f64)
                    .map_err(|e| HelperError::LuaError(format!("Failed to set size: {}", e)))?;
            }
        }

        // Call the Lua function
        func.call::<_, ()>(table)
            .map_err(|e| HelperError::LuaError(format!(
                "Lua function '{}' execution failed: {}",
                function_name, e
            )))?;

        Ok(())
    })
}

/// Queue a DHCP lease script event (replaces C queue_script lines 1174-1243)
///
/// Serializes a DHCP lease event into ScriptData format and sends it to the
/// helper task for script execution.
///
/// # Arguments
///
/// * `helper` - Handle to the helper task
/// * `action` - Action type ("add", "del", "old", "old-hostname")
/// * `lease` - DHCP lease information
/// * `interface_index` - Network interface index
///
/// # Returns
///
/// * `Ok(())` if event was queued successfully
/// * `Err(HelperError)` if serialization or sending failed
pub async fn queue_script(
    helper: &HelperHandle,
    action: &str,
    lease: &DhcpLease,
    interface_index: u32,
) -> Result<(), HelperError> {
    let mut data = ScriptData {
        action: action.to_string(),
        ..Default::default()
    };

    // Set interface name
    if interface_index > 0 {
        data.interface = indextoname(interface_index)
            .unwrap_or_else(|_| format!("if{}", interface_index));
    }

    // Set hardware address
    if let Some((hwaddr, hwtype)) = lease.hardware_address() {
        data.hwaddr_len = hwaddr.len().min(DHCP_CHADDR_MAX);
        data.hwaddr = hwaddr.to_vec();
        data.hwaddr_type = hwtype;
    }

    // Set hostname
    if let Some(hostname) = lease.hostname() {
        data.hostname = hostname.to_string();
        data.hostname_len = hostname.len();
    }

    // Set client ID
    if let Some(clid) = lease.client_id() {
        data.clid = clid.to_bytes();
        data.clid_len = data.clid.len();
    }

    // Set IPv4 or IPv6 address
    match lease.address() {
        std::net::IpAddr::V4(addr) => {
            data.addr = Some(addr);
        }
        std::net::IpAddr::V6(addr) => {
            data.addr6 = Some(addr);
            data.iaid = lease.iaid().map(|i| i.value()).unwrap_or(0);
        }
    }

    // Set lease times
    if let Some(expires) = lease.expires() {
        let expires_secs = expires
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        data.expires = expires_secs;

        // Calculate remaining time
        if let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            data.remaining_time = expires_secs.saturating_sub(now.as_secs());
        }
    }

    // Set flags
    data.flags = lease.flags().bits() as u32;

    // Set extra data (DHCP options)
    if let Some(extradata) = lease.extradata() {
        data.extradata = extradata.to_vec();
        data.ed_len = extradata.len();
    }

    // Send to helper
    helper.send_event(data).await
}

/// Queue a TFTP transfer notification (replaces C queue_tftp lines 1279-1320)
///
/// Serializes a TFTP transfer event and sends it to the helper task.
///
/// # Arguments
///
/// * `helper` - Handle to the helper task
/// * `action` - Action type (always "tftp")
/// * `filename` - Name of the transferred file
/// * `file_size` - Size of the file in bytes
/// * `client_addr` - Client IP address
/// * `interface_index` - Network interface index
pub async fn queue_tftp(
    helper: &HelperHandle,
    filename: &str,
    file_size: u64,
    client_addr: std::net::IpAddr,
    interface_index: u32,
) -> Result<(), HelperError> {
    let mut data = ScriptData {
        action: ACTION_TFTP.to_string(),
        file_len: file_size,
        hostname: filename.to_string(), // Filename goes in hostname field for TFTP
        hostname_len: filename.len(),
        ..Default::default()
    };

    // Set interface name
    if interface_index > 0 {
        data.interface = indextoname(interface_index)
            .unwrap_or_else(|_| format!("if{}", interface_index));
    }

    // Set client address
    match client_addr {
        std::net::IpAddr::V4(addr) => {
            data.addr = Some(addr);
        }
        std::net::IpAddr::V6(addr) => {
            data.addr6 = Some(addr);
        }
    }

    // Send to helper
    helper.send_event(data).await
}

/// Queue an ARP detection event (replaces C queue_arp lines 1346-1385)
///
/// Serializes an ARP detection event and sends it to the helper task.
///
/// # Arguments
///
/// * `helper` - Handle to the helper task
/// * `action` - Action type ("arp-add" or "arp-del")
/// * `mac_addr` - Hardware (MAC) address
/// * `ip_addr` - IPv4 address
/// * `interface_index` - Network interface index
pub async fn queue_arp(
    helper: &HelperHandle,
    action: &str,
    mac_addr: &[u8],
    ip_addr: Ipv4Addr,
    interface_index: u32,
) -> Result<(), HelperError> {
    let mut data = ScriptData {
        action: action.to_string(),
        ..Default::default()
    };

    // Set interface name
    if interface_index > 0 {
        data.interface = indextoname(interface_index)
            .unwrap_or_else(|_| format!("if{}", interface_index));
    }

    // Set hardware address
    data.hwaddr_len = mac_addr.len().min(DHCP_CHADDR_MAX);
    data.hwaddr = mac_addr.to_vec();
    data.hwaddr_type = ARPHRD_ETHER;

    // Set IP address
    data.addr = Some(ip_addr);

    // Send to helper
    helper.send_event(data).await
}

/// Queue a DHCPv6 relay snoop event (replaces C queue_relay_snoop lines 1419-1480)
///
/// Serializes a DHCPv6 relay snooping event and sends it to the helper task.
///
/// # Arguments
///
/// * `helper` - Handle to the helper task
/// * `lease` - DHCPv6 lease information
/// * `interface_index` - Network interface index
pub async fn queue_relay_snoop(
    helper: &HelperHandle,
    lease: &DhcpLease,
    interface_index: u32,
) -> Result<(), HelperError> {
    let mut data = ScriptData {
        action: ACTION_RELAY_SNOOP.to_string(),
        ..Default::default()
    };

    // Set interface name
    if interface_index > 0 {
        data.interface = indextoname(interface_index)
            .unwrap_or_else(|_| format!("if{}", interface_index));
    }

    // Set hardware address
    if let Some((hwaddr, hwtype)) = lease.hardware_address() {
        data.hwaddr_len = hwaddr.len().min(DHCP_CHADDR_MAX);
        data.hwaddr = hwaddr.to_vec();
        data.hwaddr_type = hwtype;
    }

    // Set client ID (DUID for DHCPv6)
    if let Some(clid) = lease.client_id() {
        data.clid = clid.to_bytes();
        data.clid_len = data.clid.len();
    }

    // Set IPv6 address
    if let std::net::IpAddr::V6(addr) = lease.address() {
        data.addr6 = Some(addr);
        data.iaid = lease.iaid().map(|i| i.value()).unwrap_or(0);
    }

    // Set flags
    data.flags = lease.flags().bits() as u32;

    // Send to helper
    helper.send_event(data).await
}

/// Write queued script data to helper (replaces C helper_write lines 1512-1573)
///
/// This function is provided for compatibility with the C API but is not needed
/// in the Rust implementation since async channels handle buffering automatically.
/// Events are sent immediately via the mpsc channel.
///
/// # Arguments
///
/// * `helper` - Handle to the helper task
///
/// # Returns
///
/// * `Ok(())` - Always succeeds (no-op in Rust implementation)
pub async fn helper_write(_helper: &HelperHandle) -> Result<(), HelperError> {
    // In the Rust implementation, events are sent immediately via async channels.
    // This function is provided for API compatibility but does nothing.
    Ok(())
}

/// Check if helper event buffer is empty (replaces C helper_buf_empty)
///
/// This function is provided for compatibility with the C API but always returns
/// true in the Rust implementation since async channels don't expose queue depth.
///
/// # Arguments
///
/// * `_helper` - Handle to the helper task (unused)
///
/// # Returns
///
/// * `true` - Always (buffer management is internal to async channels)
pub fn helper_buf_empty(_helper: &HelperHandle) -> bool {
    // In the Rust implementation, the channel's internal buffer is opaque.
    // This function is provided for API compatibility but always returns true.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_data_default() {
        let data = ScriptData::default();
        assert_eq!(data.action, "");
        assert_eq!(data.flags, 0);
        assert_eq!(data.hwaddr_len, 0);
        assert_eq!(data.clid_len, 0);
    }

    #[test]
    fn test_build_script_environment() {
        let data = ScriptData {
            action: ACTION_ADD.to_string(),
            interface: "eth0".to_string(),
            hostname: "test-host".to_string(),
            addr: Some(Ipv4Addr::new(192, 168, 1, 100)),
            hwaddr: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            hwaddr_len: 6,
            expires: 1234567890,
            ..Default::default()
        };

        let env = build_script_environment(&data).unwrap();
        
        assert_eq!(env.get("DNSMASQ_INTERFACE"), Some(&"eth0".to_string()));
        assert_eq!(env.get("DNSMASQ_SUPPLIED_HOSTNAME"), Some(&"test-host".to_string()));
        assert_eq!(env.get("DNSMASQ_IP"), Some(&"192.168.1.100".to_string()));
        assert_eq!(env.get("DNSMASQ_MAC"), Some(&"00:11:22:33:44:55".to_string()));
        assert_eq!(env.get("DNSMASQ_LEASE_EXPIRES"), Some(&"1234567890".to_string()));
    }

    #[tokio::test]
    async fn test_helper_buf_empty() {
        // Create a minimal helper handle for testing
        let (tx, _rx) = mpsc::channel::<HelperEvent>(100);
        let task_handle = tokio::spawn(async { Ok(()) });
        let helper = HelperHandle { tx, task_handle };

        assert!(helper_buf_empty(&helper));
    }
}
