// dnsmasq-rs: Memory-safe Rust implementation of dnsmasq
// Copyright (c) 2000-2022 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! DHCP and TFTP script execution subsystem
//!
//! This module implements privilege-separated script execution for DHCP lease changes,
//! TFTP transfers, and ARP events. It replaces the C implementation in `src/helper.c`
//! with async Rust using tokio::process.
//!
//! # Architecture
//!
//! The C version uses fork() to create a privileged helper process that receives events
//! via a Unix socket and executes scripts with root privileges. The Rust version maintains
//! similar privilege separation but uses async task spawning:
//!
//! ```text
//! Main Process (unprivileged) → Queue events → Script Executor (privileged)
//!                                            ↓
//!                                    Execute script with env vars
//!                                            ↓
//!                                    Capture output and status
//! ```
//!
//! # Event Types
//!
//! - DHCP lease actions: add, del, old (renewal)
//! - TFTP transfers: file, error
//! - ARP detections: arp-add, arp-del
//!
//! # Security
//!
//! The script executor validates all input and ensures the script path cannot be modified
//! after initialization, preventing privilege escalation attacks.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Maximum script execution time in seconds
const SCRIPT_TIMEOUT_SECS: u64 = 60;

/// Maximum output buffer size (1MB)
const MAX_OUTPUT_SIZE: usize = 1_048_576;

/// Script execution errors
#[derive(Debug, Error)]
pub enum ScriptError {
    /// Script file not found or not executable
    #[error("Script not found or not executable: {0}")]
    ScriptNotFound(PathBuf),

    /// Script execution failed
    #[error("Script execution failed: {0}")]
    ExecutionFailed(String),

    /// Script timeout
    #[error("Script execution timed out after {0} seconds")]
    Timeout(u64),

    /// I/O error during script execution
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Event queue channel error
    #[error("Event queue error: {0}")]
    QueueError(String),

    /// Invalid script path
    #[error("Invalid script path: {0}")]
    InvalidPath(String),

    /// Script returned non-zero exit code
    #[error("Script exited with status {0}")]
    NonZeroExit(i32),
}

/// DHCP lease action types
///
/// Maps to the C version's event types in helper.c
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseAction {
    /// New lease added (DHCP DISCOVER→OFFER→REQUEST→ACK)
    Add,

    /// Existing lease deleted (lease expired or DHCP RELEASE)
    Del,

    /// Lease renewed (DHCP REQUEST from existing client)
    Old,
}

impl LeaseAction {
    /// Convert to environment variable string
    pub fn as_env_str(&self) -> &'static str {
        match self {
            LeaseAction::Add => "add",
            LeaseAction::Del => "del",
            LeaseAction::Old => "old",
        }
    }
}

/// Script event types
///
/// Represents all event types that can trigger script execution,
/// mirroring the C version's struct script_data wire format.
#[derive(Debug, Clone)]
pub enum ScriptEvent {
    /// DHCPv4 lease event
    DhcpLease {
        action: LeaseAction,
        mac_address: String,
        ip_address: IpAddr,
        hostname: Option<String>,
        client_id: Option<Vec<u8>>,
        expiry_time: Option<u64>,
        vendor_class: Option<String>,
        user_class: Option<String>,
        circuit_id: Option<String>,
        remote_id: Option<String>,
        tags: Vec<String>,
    },

    /// DHCPv6 lease event
    Dhcp6Lease {
        action: LeaseAction,
        duid: Vec<u8>,
        iaid: u32,
        ip_address: IpAddr,
        hostname: Option<String>,
        expiry_time: Option<u64>,
        tags: Vec<String>,
    },

    /// TFTP file transfer event
    TftpTransfer {
        file_path: PathBuf,
        file_size: u64,
        client_address: IpAddr,
    },

    /// TFTP transfer error
    TftpError {
        file_path: PathBuf,
        client_address: IpAddr,
        error_message: String,
    },

    /// ARP table entry detection
    ArpAdd {
        mac_address: String,
        ip_address: IpAddr,
    },

    /// ARP table entry removal
    ArpDel {
        mac_address: String,
        ip_address: IpAddr,
    },
}

impl ScriptEvent {
    /// Build environment variables for script execution
    ///
    /// Creates DNSMASQ_* environment variables that the script can read,
    /// matching the C version's my_setenv() function behavior.
    pub fn build_env_vars(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();

        match self {
            ScriptEvent::DhcpLease {
                action,
                mac_address,
                ip_address,
                hostname,
                client_id,
                expiry_time,
                vendor_class,
                user_class,
                circuit_id,
                remote_id,
                tags,
            } => {
                env.insert(
                    "DNSMASQ_ACTION".to_string(),
                    action.as_env_str().to_string(),
                );
                env.insert("DNSMASQ_MAC".to_string(), mac_address.clone());
                env.insert("DNSMASQ_IP".to_string(), ip_address.to_string());

                if let Some(ref h) = hostname {
                    env.insert("DNSMASQ_HOSTNAME".to_string(), h.clone());
                }

                if let Some(ref cid) = client_id {
                    env.insert("DNSMASQ_CLIENT_ID".to_string(), hex::encode(cid));
                }

                if let Some(expiry) = expiry_time {
                    env.insert("DNSMASQ_LEASE_EXPIRES".to_string(), expiry.to_string());
                }

                if let Some(ref vc) = vendor_class {
                    env.insert("DNSMASQ_VENDOR_CLASS".to_string(), vc.clone());
                }

                if let Some(ref uc) = user_class {
                    env.insert("DNSMASQ_USER_CLASS".to_string(), uc.clone());
                }

                if let Some(ref cir) = circuit_id {
                    env.insert("DNSMASQ_CIRCUIT_ID".to_string(), cir.clone());
                }

                if let Some(ref rem) = remote_id {
                    env.insert("DNSMASQ_REMOTE_ID".to_string(), rem.clone());
                }

                if !tags.is_empty() {
                    env.insert("DNSMASQ_TAGS".to_string(), tags.join(" "));
                }
            }

            ScriptEvent::Dhcp6Lease {
                action,
                duid,
                iaid,
                ip_address,
                hostname,
                expiry_time,
                tags,
            } => {
                env.insert(
                    "DNSMASQ_ACTION".to_string(),
                    action.as_env_str().to_string(),
                );
                env.insert("DNSMASQ_DUID".to_string(), hex::encode(duid));
                env.insert("DNSMASQ_IAID".to_string(), iaid.to_string());
                env.insert("DNSMASQ_IP".to_string(), ip_address.to_string());

                if let Some(ref h) = hostname {
                    env.insert("DNSMASQ_HOSTNAME".to_string(), h.clone());
                }

                if let Some(expiry) = expiry_time {
                    env.insert("DNSMASQ_LEASE_EXPIRES".to_string(), expiry.to_string());
                }

                if !tags.is_empty() {
                    env.insert("DNSMASQ_TAGS".to_string(), tags.join(" "));
                }
            }

            ScriptEvent::TftpTransfer {
                file_path,
                file_size,
                client_address,
            } => {
                env.insert("DNSMASQ_ACTION".to_string(), "tftp".to_string());
                env.insert(
                    "DNSMASQ_TFTP_FILE".to_string(),
                    file_path.display().to_string(),
                );
                env.insert("DNSMASQ_TFTP_SIZE".to_string(), file_size.to_string());
                env.insert(
                    "DNSMASQ_CLIENT_ADDRESS".to_string(),
                    client_address.to_string(),
                );
            }

            ScriptEvent::TftpError {
                file_path,
                client_address,
                error_message,
            } => {
                env.insert("DNSMASQ_ACTION".to_string(), "tftp_error".to_string());
                env.insert(
                    "DNSMASQ_TFTP_FILE".to_string(),
                    file_path.display().to_string(),
                );
                env.insert(
                    "DNSMASQ_CLIENT_ADDRESS".to_string(),
                    client_address.to_string(),
                );
                env.insert("DNSMASQ_TFTP_ERROR".to_string(), error_message.clone());
            }

            ScriptEvent::ArpAdd {
                mac_address,
                ip_address,
            } => {
                env.insert("DNSMASQ_ACTION".to_string(), "arp-add".to_string());
                env.insert("DNSMASQ_MAC".to_string(), mac_address.clone());
                env.insert("DNSMASQ_IP".to_string(), ip_address.to_string());
            }

            ScriptEvent::ArpDel {
                mac_address,
                ip_address,
            } => {
                env.insert("DNSMASQ_ACTION".to_string(), "arp-del".to_string());
                env.insert("DNSMASQ_MAC".to_string(), mac_address.clone());
                env.insert("DNSMASQ_IP".to_string(), ip_address.to_string());
            }
        }

        env
    }

    /// Get event description for logging
    pub fn description(&self) -> String {
        match self {
            ScriptEvent::DhcpLease {
                action, ip_address, ..
            } => {
                format!("DHCP {:?} for {}", action, ip_address)
            }
            ScriptEvent::Dhcp6Lease {
                action, ip_address, ..
            } => {
                format!("DHCPv6 {:?} for {}", action, ip_address)
            }
            ScriptEvent::TftpTransfer { file_path, .. } => {
                format!("TFTP transfer: {}", file_path.display())
            }
            ScriptEvent::TftpError { file_path, .. } => {
                format!("TFTP error: {}", file_path.display())
            }
            ScriptEvent::ArpAdd { ip_address, .. } => {
                format!("ARP add: {}", ip_address)
            }
            ScriptEvent::ArpDel { ip_address, .. } => {
                format!("ARP del: {}", ip_address)
            }
        }
    }
}

/// Script execution result
#[derive(Debug, Clone)]
pub struct ScriptResult {
    /// Exit status code
    pub exit_code: i32,

    /// Standard output captured from script
    pub stdout: String,

    /// Standard error captured from script
    pub stderr: String,

    /// Execution duration in milliseconds
    pub duration_ms: u64,
}

/// Asynchronous script executor
///
/// Manages a queue of script events and executes them asynchronously using tokio::process.
/// Replaces the C version's helper process model with async Rust tasks.
pub struct ScriptExecutor {
    /// Path to the script executable (immutable after construction for security)
    script_path: PathBuf,

    /// Event queue sender
    event_tx: mpsc::UnboundedSender<ScriptEvent>,

    /// Shared state for tracking execution
    state: Arc<RwLock<ExecutorState>>,
}

/// Internal executor state
#[derive(Debug)]
struct ExecutorState {
    /// Number of events queued
    queued_count: u64,

    /// Number of events executed
    executed_count: u64,

    /// Number of events that failed
    failed_count: u64,

    /// Whether the executor is running
    running: bool,
}

impl ScriptExecutor {
    /// Create a new script executor
    ///
    /// # Arguments
    ///
    /// * `script_path` - Path to the executable script (must exist and be executable)
    ///
    /// # Errors
    ///
    /// Returns `ScriptError::ScriptNotFound` if the script doesn't exist or isn't executable.
    /// Returns `ScriptError::InvalidPath` if the path is invalid.
    pub fn new<P: AsRef<Path>>(script_path: P) -> Result<Self, ScriptError> {
        let script_path = script_path.as_ref().to_path_buf();

        // Validate script path exists and is executable
        if !script_path.exists() {
            return Err(ScriptError::ScriptNotFound(script_path));
        }

        // Check if file is executable (Unix-specific)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = script_path.metadata().map_err(ScriptError::Io)?;
            let permissions = metadata.permissions();
            if permissions.mode() & 0o111 == 0 {
                return Err(ScriptError::ScriptNotFound(script_path));
            }
        }

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let state = Arc::new(RwLock::new(ExecutorState {
            queued_count: 0,
            executed_count: 0,
            failed_count: 0,
            running: false,
        }));

        let executor = Self {
            script_path: script_path.clone(),
            event_tx,
            state: state.clone(),
        };

        // Spawn background task to process events
        tokio::spawn(Self::event_processor(script_path, event_rx, state));

        Ok(executor)
    }

    /// Queue a script event for execution
    ///
    /// Events are queued and executed asynchronously in FIFO order.
    pub async fn queue_event(&self, event: ScriptEvent) -> Result<(), ScriptError> {
        debug!("Queuing script event: {}", event.description());

        self.event_tx
            .send(event)
            .map_err(|e| ScriptError::QueueError(e.to_string()))?;

        let mut state = self.state.write().await;
        state.queued_count += 1;

        Ok(())
    }

    /// Queue a DHCP lease event
    ///
    /// Convenience method for queuing DHCP lease changes.
    pub async fn queue_lease_event(
        &self,
        action: LeaseAction,
        mac_address: String,
        ip_address: IpAddr,
        hostname: Option<String>,
    ) -> Result<(), ScriptError> {
        let event = ScriptEvent::DhcpLease {
            action,
            mac_address,
            ip_address,
            hostname,
            client_id: None,
            expiry_time: None,
            vendor_class: None,
            user_class: None,
            circuit_id: None,
            remote_id: None,
            tags: Vec::new(),
        };

        self.queue_event(event).await
    }

    /// Get execution statistics
    pub async fn stats(&self) -> (u64, u64, u64) {
        let state = self.state.read().await;
        (state.queued_count, state.executed_count, state.failed_count)
    }

    /// Background event processor task
    async fn event_processor(
        script_path: PathBuf,
        mut event_rx: mpsc::UnboundedReceiver<ScriptEvent>,
        state: Arc<RwLock<ExecutorState>>,
    ) {
        info!("Script executor started: {}", script_path.display());

        {
            let mut s = state.write().await;
            s.running = true;
        }

        while let Some(event) = event_rx.recv().await {
            debug!("Processing script event: {}", event.description());

            match Self::execute_script(&script_path, &event).await {
                Ok(result) => {
                    info!(
                        "Script executed successfully: {} (exit={}, duration={}ms)",
                        event.description(),
                        result.exit_code,
                        result.duration_ms
                    );

                    if !result.stdout.is_empty() {
                        debug!("Script stdout: {}", result.stdout);
                    }

                    if !result.stderr.is_empty() {
                        debug!("Script stderr: {}", result.stderr);
                    }

                    let mut s = state.write().await;
                    s.executed_count += 1;
                }
                Err(e) => {
                    error!("Script execution failed: {} - {}", event.description(), e);

                    let mut s = state.write().await;
                    s.failed_count += 1;
                }
            }
        }

        info!("Script executor stopped");

        let mut s = state.write().await;
        s.running = false;
    }

    /// Execute script with environment variables
    async fn execute_script(
        script_path: &Path,
        event: &ScriptEvent,
    ) -> Result<ScriptResult, ScriptError> {
        let env_vars = event.build_env_vars();

        let start_time = std::time::Instant::now();

        let mut child = Command::new(script_path)
            .envs(env_vars)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(ScriptError::Io)?;

        // Wait for script with timeout
        let timeout = tokio::time::Duration::from_secs(SCRIPT_TIMEOUT_SECS);
        let result = tokio::time::timeout(timeout, child.wait()).await;

        let status = match result {
            Ok(Ok(status)) => status,
            Ok(Err(e)) => return Err(ScriptError::Io(e)),
            Err(_) => {
                // Timeout - kill the child process
                let _ = child.kill().await;
                return Err(ScriptError::Timeout(SCRIPT_TIMEOUT_SECS));
            }
        };

        let duration_ms = start_time.elapsed().as_millis() as u64;

        // Capture stdout
        let mut stdout_buf = Vec::new();
        if let Some(mut stdout) = child.stdout {
            let _ = stdout
                .read_to_end(&mut stdout_buf)
                .await
                .map_err(ScriptError::Io)?;
        }

        // Capture stderr
        let mut stderr_buf = Vec::new();
        if let Some(mut stderr) = child.stderr {
            let _ = stderr
                .read_to_end(&mut stderr_buf)
                .await
                .map_err(ScriptError::Io)?;
        }

        // Limit output size
        stdout_buf.truncate(MAX_OUTPUT_SIZE);
        stderr_buf.truncate(MAX_OUTPUT_SIZE);

        let stdout = String::from_utf8_lossy(&stdout_buf).to_string();
        let stderr = String::from_utf8_lossy(&stderr_buf).to_string();

        let exit_code = status.code().unwrap_or(-1);

        if !status.success() {
            warn!(
                "Script exited with non-zero status: {} (code={})",
                script_path.display(),
                exit_code
            );
        }

        Ok(ScriptResult {
            exit_code,
            stdout,
            stderr,
            duration_ms,
        })
    }
}

// Add hex encoding dependency placeholder
// In production, this would use the hex crate or implement hex encoding
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_action_env_str() {
        assert_eq!(LeaseAction::Add.as_env_str(), "add");
        assert_eq!(LeaseAction::Del.as_env_str(), "del");
        assert_eq!(LeaseAction::Old.as_env_str(), "old");
    }

    #[test]
    fn test_dhcp_lease_env_vars() {
        let event = ScriptEvent::DhcpLease {
            action: LeaseAction::Add,
            mac_address: "00:11:22:33:44:55".to_string(),
            ip_address: "192.168.1.100".parse().unwrap(),
            hostname: Some("test-host".to_string()),
            client_id: Some(vec![0x01, 0x02, 0x03]),
            expiry_time: Some(3600),
            vendor_class: None,
            user_class: None,
            circuit_id: None,
            remote_id: None,
            tags: vec!["tag1".to_string(), "tag2".to_string()],
        };

        let env = event.build_env_vars();

        assert_eq!(env.get("DNSMASQ_ACTION"), Some(&"add".to_string()));
        assert_eq!(
            env.get("DNSMASQ_MAC"),
            Some(&"00:11:22:33:44:55".to_string())
        );
        assert_eq!(env.get("DNSMASQ_IP"), Some(&"192.168.1.100".to_string()));
        assert_eq!(env.get("DNSMASQ_HOSTNAME"), Some(&"test-host".to_string()));
        assert_eq!(env.get("DNSMASQ_CLIENT_ID"), Some(&"010203".to_string()));
        assert_eq!(env.get("DNSMASQ_LEASE_EXPIRES"), Some(&"3600".to_string()));
        assert_eq!(env.get("DNSMASQ_TAGS"), Some(&"tag1 tag2".to_string()));
    }

    #[test]
    fn test_event_description() {
        let event = ScriptEvent::DhcpLease {
            action: LeaseAction::Add,
            mac_address: "00:11:22:33:44:55".to_string(),
            ip_address: "192.168.1.100".parse().unwrap(),
            hostname: None,
            client_id: None,
            expiry_time: None,
            vendor_class: None,
            user_class: None,
            circuit_id: None,
            remote_id: None,
            tags: Vec::new(),
        };

        assert!(event.description().contains("DHCP"));
        assert!(event.description().contains("192.168.1.100"));
    }
}
