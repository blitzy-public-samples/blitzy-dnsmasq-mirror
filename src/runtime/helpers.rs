//! Helper process spawning for DHCP script execution
//!
//! This module replaces C's fork/pipe/exec pattern with Tokio's process management,
//! providing async script execution for DHCP lease-change events.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{error, info, warn};

#[cfg(feature = "lua")]
use mlua::{Lua, Value};

/// Script events for DHCP lease changes and network events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScriptEvent {
    /// DHCP lease added (action: "add")
    DhcpLease {
        mac: String,
        ip: String,
        hostname: String,
        interface: String,
        expiry: u64,
        client_id: Option<String>,
        tags: Vec<String>,
        vendor_class: Option<String>,
        supplied_hostname: Option<String>,
        circuit_id: Option<String>,
        remote_id: Option<String>,
        subscriber_id: Option<String>,
    },
    
    /// DHCP lease renewed with old IP (action: "old")
    DhcpLeaseOld {
        mac: String,
        ip: String,
        hostname: String,
        interface: String,
        expiry: u64,
        client_id: Option<String>,
    },
    
    /// DHCP lease deleted (action: "del")
    DhcpLeaseDel {
        mac: String,
        ip: String,
        hostname: String,
        interface: String,
    },
    
    /// TFTP transfer (action: "tftp")
    TftpTransfer {
        file_size: u64,
        destination: String,
        filename: String,
        interface: String,
    },
    
    /// ARP addition (action: "arp-add")
    ArpAdd {
        mac: String,
        ip: String,
        interface: String,
    },
    
    /// ARP deletion (action: "arp-del")
    ArpDel {
        mac: String,
        ip: String,
        interface: String,
    },
    
    /// DHCP relay snoop
    RelaySnoop {
        mac: String,
        ip: String,
        interface: String,
    },
}

impl ScriptEvent {
    /// Get the action string for this event
    fn action(&self) -> &str {
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
    
    /// Build environment variables for script execution
    fn build_environment(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("DNSMASQ_LEASE_ACTION".to_string(), self.action().to_string());
        
        match self {
            ScriptEvent::DhcpLease {
                mac, ip, hostname, interface, expiry, client_id,
                tags, vendor_class, supplied_hostname, circuit_id,
                remote_id, subscriber_id,
            } => {
                env.insert("DNSMASQ_CLIENT_ID".to_string(), mac.clone());
                env.insert("DNSMASQ_INTERFACE".to_string(), interface.clone());
                env.insert("DNSMASQ_LEASE_EXPIRES".to_string(), expiry.to_string());
                
                if let Some(cid) = client_id {
                    env.insert("DNSMASQ_CLIENT_ID".to_string(), cid.clone());
                }
                if !tags.is_empty() {
                    env.insert("DNSMASQ_TAGS".to_string(), tags.join(" "));
                }
                if let Some(vc) = vendor_class {
                    env.insert("DNSMASQ_VENDOR_CLASS".to_string(), vc.clone());
                }
                if let Some(sh) = supplied_hostname {
                    env.insert("DNSMASQ_SUPPLIED_HOSTNAME".to_string(), sh.clone());
                }
                if let Some(ci) = circuit_id {
                    env.insert("DNSMASQ_CIRCUIT_ID".to_string(), ci.clone());
                }
                if let Some(ri) = remote_id {
                    env.insert("DNSMASQ_REMOTE_ID".to_string(), ri.clone());
                }
                if let Some(si) = subscriber_id {
                    env.insert("DNSMASQ_SUBSCRIBER_ID".to_string(), si.clone());
                }
            }
            ScriptEvent::DhcpLeaseOld {
                mac, ip, hostname, interface, expiry, client_id,
            } => {
                env.insert("DNSMASQ_CLIENT_ID".to_string(), mac.clone());
                env.insert("DNSMASQ_INTERFACE".to_string(), interface.clone());
                env.insert("DNSMASQ_LEASE_EXPIRES".to_string(), expiry.to_string());
                
                if let Some(cid) = client_id {
                    env.insert("DNSMASQ_CLIENT_ID".to_string(), cid.clone());
                }
            }
            ScriptEvent::DhcpLeaseDel { mac, ip, hostname, interface } => {
                env.insert("DNSMASQ_CLIENT_ID".to_string(), mac.clone());
                env.insert("DNSMASQ_INTERFACE".to_string(), interface.clone());
            }
            ScriptEvent::TftpTransfer { file_size, destination, filename, interface } => {
                env.insert("DNSMASQ_TFTP_FILE_SIZE".to_string(), file_size.to_string());
                env.insert("DNSMASQ_TFTP_DESTINATION".to_string(), destination.clone());
                env.insert("DNSMASQ_TFTP_FILE".to_string(), filename.clone());
                env.insert("DNSMASQ_INTERFACE".to_string(), interface.clone());
            }
            ScriptEvent::ArpAdd { mac, ip, interface } |
            ScriptEvent::ArpDel { mac, ip, interface } |
            ScriptEvent::RelaySnoop { mac, ip, interface } => {
                env.insert("DNSMASQ_CLIENT_ID".to_string(), mac.clone());
                env.insert("DNSMASQ_INTERFACE".to_string(), interface.clone());
            }
        }
        
        env
    }
    
    /// Get positional arguments for script execution
    fn script_args(&self) -> Vec<String> {
        match self {
            ScriptEvent::DhcpLease { mac, ip, hostname, .. } |
            ScriptEvent::DhcpLeaseOld { mac, ip, hostname, .. } |
            ScriptEvent::DhcpLeaseDel { mac, ip, hostname, .. } => {
                vec![self.action().to_string(), mac.clone(), ip.clone(), hostname.clone()]
            }
            ScriptEvent::TftpTransfer { file_size, destination, filename, .. } => {
                vec![
                    self.action().to_string(),
                    file_size.to_string(),
                    destination.clone(),
                    filename.clone(),
                ]
            }
            ScriptEvent::ArpAdd { mac, ip, .. } |
            ScriptEvent::ArpDel { mac, ip, .. } |
            ScriptEvent::RelaySnoop { mac, ip, .. } => {
                vec![self.action().to_string(), mac.clone(), ip.clone()]
            }
        }
    }
}

/// Helper process errors
#[derive(Error, Debug)]
pub enum HelperError {
    /// Failed to spawn script
    #[error("Failed to spawn script '{path}': {error}")]
    FailedToSpawnScript {
        path: String,
        error: std::io::Error,
    },
    
    /// Script execution timeout
    #[error("Script timed out after {duration:?}")]
    ScriptTimeout {
        duration: Duration,
    },
    
    /// Script exited with non-zero status
    #[error("Script exited with code {code}")]
    ScriptNonZeroExit {
        code: i32,
    },
    
    /// Event channel closed
    #[error("Event channel closed")]
    ChannelClosed,
    
    /// Lua script error
    #[cfg(feature = "lua")]
    #[error("Lua error: {0}")]
    LuaError(#[from] mlua::Error),
    
    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Handle for sending events to helper task
pub struct HelperHandle {
    sender: mpsc::UnboundedSender<ScriptEvent>,
}

impl HelperHandle {
    /// Send an event to the helper task
    pub fn send_event(&self, event: ScriptEvent) -> Result<(), HelperError> {
        self.sender.send(event).map_err(|_| HelperError::ChannelClosed)
    }
    
    /// Check if the helper task is closed
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
    
    /// Close the helper task
    pub fn close(&self) {
        // Sender will close when dropped
    }
}

/// Spawn helper process task for script execution
///
/// Creates a background task that processes script events asynchronously.
/// Scripts are executed with appropriate environment variables and arguments.
///
/// # Arguments
///
/// * `script_path` - Optional path to DHCP script to execute
/// * `lua_script_path` - Optional path to Lua script to execute
/// * `script_timeout` - Maximum time to wait for script completion
///
/// # Returns
///
/// HelperHandle for sending events to the helper task
pub fn spawn_helper_process(
    script_path: Option<PathBuf>,
    #[allow(unused_variables)]
    lua_script_path: Option<PathBuf>,
    script_timeout: Duration,
) -> Result<HelperHandle, HelperError> {
    info!("Spawning helper process task");
    
    // Validate script paths exist
    if let Some(ref path) = script_path {
        if !path.exists() {
            warn!("Script path does not exist: {}", path.display());
        }
    }
    
    #[cfg(feature = "lua")]
    let lua = if let Some(ref path) = lua_script_path {
        if !path.exists() {
            warn!("Lua script path does not exist: {}", path.display());
            None
        } else {
            match init_lua_script(path) {
                Ok(lua) => {
                    info!("Lua script loaded: {}", path.display());
                    Some(lua)
                }
                Err(e) => {
                    error!("Failed to load Lua script: {}", e);
                    None
                }
            }
        }
    } else {
        None
    };
    
    let (sender, mut receiver) = mpsc::unbounded_channel::<ScriptEvent>();
    
    // Spawn background task
    tokio::spawn(async move {
        info!("Helper task started");
        
        while let Some(event) = receiver.recv().await {
            info!("Processing event: {:?}", event.action());
            
            // Execute Lua script if available
            #[cfg(feature = "lua")]
            if let Some(ref lua) = lua {
                if let Err(e) = execute_lua_script(lua, &event).await {
                    error!("Lua script error: {}", e);
                }
            }
            
            // Execute shell script if available
            if let Some(ref path) = script_path {
                if let Err(e) = execute_script(path, &event, script_timeout).await {
                    error!("Script execution error: {}", e);
                }
            }
        }
        
        info!("Helper task shutting down");
    });
    
    Ok(HelperHandle { sender })
}

/// Execute a shell script with event data
async fn execute_script(
    script_path: &Path,
    event: &ScriptEvent,
    script_timeout: Duration,
) -> Result<(), HelperError> {
    let args = event.script_args();
    let env = event.build_environment();
    
    info!("Executing script: {} {:?}", script_path.display(), args);
    
    let mut cmd = Command::new(script_path);
    cmd.args(&args)
        .envs(&env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    
    let mut child = cmd.spawn()
        .map_err(|e| HelperError::FailedToSpawnScript {
            path: script_path.display().to_string(),
            error: e,
        })?;
    
    // Capture stdout and stderr
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    
    if let Some(stdout) = stdout {
        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                info!("Script stdout: {}", line);
            }
        });
    }
    
    if let Some(stderr) = stderr {
        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                warn!("Script stderr: {}", line);
            }
        });
    }
    
    // Wait for completion with timeout
    let wait_result = timeout(script_timeout, child.wait()).await;
    
    match wait_result {
        Ok(Ok(status)) => {
            if status.success() {
                info!("Script completed successfully");
                Ok(())
            } else {
                let code = status.code().unwrap_or(-1);
                warn!("Script exited with code: {}", code);
                Err(HelperError::ScriptNonZeroExit { code })
            }
        }
        Ok(Err(e)) => {
            error!("Script wait error: {}", e);
            Err(HelperError::IoError(e))
        }
        Err(_) => {
            warn!("Script timed out after {:?}", script_timeout);
            Err(HelperError::ScriptTimeout { duration: script_timeout })
        }
    }
}

/// Initialize Lua script
#[cfg(feature = "lua")]
fn init_lua_script(script_path: &Path) -> Result<Lua, mlua::Error> {
    let lua = Lua::new();
    lua.load(std::fs::read_to_string(script_path)?).exec()?;
    Ok(lua)
}

/// Execute Lua script callback
#[cfg(feature = "lua")]
async fn execute_lua_script(lua: &Lua, event: &ScriptEvent) -> Result<(), mlua::Error> {
    let globals = lua.globals();
    
    match event {
        ScriptEvent::DhcpLease { mac, ip, hostname, .. } => {
            if let Ok(func) = globals.get::<_, mlua::Function>("lease") {
                func.call::<_, ()>((event.action(), mac.clone(), ip.clone(), hostname.clone()))?;
            }
        }
        ScriptEvent::DhcpLeaseOld { mac, ip, hostname, .. } => {
            if let Ok(func) = globals.get::<_, mlua::Function>("lease") {
                func.call::<_, ()>((event.action(), mac.clone(), ip.clone(), hostname.clone()))?;
            }
        }
        ScriptEvent::DhcpLeaseDel { mac, ip, hostname, .. } => {
            if let Ok(func) = globals.get::<_, mlua::Function>("lease") {
                func.call::<_, ()>((event.action(), mac.clone(), ip.clone(), hostname.clone()))?;
            }
        }
        ScriptEvent::TftpTransfer { file_size, destination, filename, .. } => {
            if let Ok(func) = globals.get::<_, mlua::Function>("tftp") {
                func.call::<_, ()>((*file_size, destination.clone(), filename.clone()))?;
            }
        }
        ScriptEvent::ArpAdd { mac, ip, .. } | ScriptEvent::ArpDel { mac, ip, .. } => {
            if let Ok(func) = globals.get::<_, mlua::Function>("arp") {
                func.call::<_, ()>((event.action(), mac.clone(), ip.clone()))?;
            }
        }
        ScriptEvent::RelaySnoop { mac, ip, .. } => {
            if let Ok(func) = globals.get::<_, mlua::Function>("snoop") {
                func.call::<_, ()>((mac.clone(), ip.clone()))?;
            }
        }
    }
    
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
            expiry: 3600,
            client_id: None,
            tags: vec![],
            vendor_class: None,
            supplied_hostname: None,
            circuit_id: None,
            remote_id: None,
            subscriber_id: None,
        };
        
        assert_eq!(event.action(), "add");
    }
    
    #[test]
    fn test_build_environment() {
        let event = ScriptEvent::DhcpLease {
            mac: "00:11:22:33:44:55".to_string(),
            ip: "192.168.1.100".to_string(),
            hostname: "test".to_string(),
            interface: "eth0".to_string(),
            expiry: 3600,
            client_id: None,
            tags: vec![],
            vendor_class: None,
            supplied_hostname: None,
            circuit_id: None,
            remote_id: None,
            subscriber_id: None,
        };
        
        let env = event.build_environment();
        assert_eq!(env.get("DNSMASQ_LEASE_ACTION"), Some(&"add".to_string()));
        assert_eq!(env.get("DNSMASQ_INTERFACE"), Some(&"eth0".to_string()));
    }
    
    #[test]
    fn test_script_args() {
        let event = ScriptEvent::DhcpLease {
            mac: "00:11:22:33:44:55".to_string(),
            ip: "192.168.1.100".to_string(),
            hostname: "test".to_string(),
            interface: "eth0".to_string(),
            expiry: 3600,
            client_id: None,
            tags: vec![],
            vendor_class: None,
            supplied_hostname: None,
            circuit_id: None,
            remote_id: None,
            subscriber_id: None,
        };
        
        let args = event.script_args();
        assert_eq!(args.len(), 4);
        assert_eq!(args[0], "add");
        assert_eq!(args[1], "00:11:22:33:44:55");
    }
}
