//! Daemonization and privilege management for dnsmasq-rs
//!
//! This module handles the daemon lifecycle including fork-to-background,
//! privilege dropping, and PID file management. It replaces C's manual
//! fork/setuid/setgid with safe Rust abstractions using the nix crate.

use anyhow::Context;
use nix::unistd::{
    fork, setsid, setuid, setgid, setgroups, getuid, getpid,
    Uid, Gid, User, Group, ForkResult, dup2, fchown,
};
use std::fs::{File, OpenOptions, remove_file};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{info, warn, error};

/// Daemon configuration
#[derive(Debug, Clone, Default)]
pub struct DaemonConfig {
    /// Whether to fork to background
    pub daemonize: bool,
    
    /// Debug mode (don't fork, verbose logging)
    pub debug: bool,
    
    /// PID file path
    pub pid_file: Option<PathBuf>,
}

/// Privilege configuration for dropping root
#[derive(Debug, Clone)]
pub struct PrivilegeConfig {
    /// User to drop privileges to
    pub user: Option<String>,
    
    /// Group to drop privileges to  
    pub group: Option<String>,
    
    /// Whether to drop privileges after binding
    pub drop_after_bind: bool,
}

impl Default for PrivilegeConfig {
    fn default() -> Self {
        Self {
            user: None,
            group: None,
            drop_after_bind: true,
        }
    }
}

/// Errors that can occur during daemon operations
#[derive(Error, Debug)]
pub enum DaemonError {
    /// Fork operation failed
    #[error("Failed to fork process: {0}")]
    ForkFailed(String),
    
    /// PID file operation failed
    #[error("PID file error: {0}")]
    PidFileError(String),
    
    /// Privilege dropping failed
    #[error("Failed to drop privileges: {0}")]
    PrivilegeDropFailed(String),
    
    /// User not found
    #[error("User not found: {username}")]
    UserNotFound { username: String },
    
    /// Group not found
    #[error("Group not found: {groupname}")]
    GroupNotFound { groupname: String },
    
    /// Capability management error (Linux-specific)
    #[error("Capability error: {0}")]
    CapabilityError(String),
    
    /// Session creation failed
    #[error("Failed to create new session: {0}")]
    SessionCreationFailed(String),
    
    /// File descriptor redirection failed
    #[error("Failed to redirect file descriptors: {0}")]
    RedirectionFailed(String),
    
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    /// nix error
    #[error("System call error: {0}")]
    Nix(#[from] nix::Error),
}

/// PID file handle with automatic cleanup
pub struct PidFile {
    path: PathBuf,
}

impl PidFile {
    /// Get the PID file path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if let Err(e) = remove_file(&self.path) {
            warn!("Failed to remove PID file {:?}: {}", self.path, e);
        } else {
            info!("Removed PID file {:?}", self.path);
        }
    }
}

/// Fork the process to background (daemonize)
///
/// Implements the double-fork pattern to fully detach from the terminal:
/// 1. First fork creates child and parent exits
/// 2. setsid() creates new session
/// 3. Second fork ensures process can't acquire controlling terminal
/// 4. Redirect stdin/stdout/stderr to /dev/null
///
/// # Arguments
///
/// * `config` - Daemon configuration
///
/// # Returns
///
/// Ok(()) if daemon fork succeeded, Err if fork failed
pub fn daemonize(config: &DaemonConfig) -> Result<(), DaemonError> {
    // Skip daemonization if not requested or in debug mode
    if !config.daemonize || config.debug {
        info!("Skipping daemonization (daemonize={}, debug={})", 
              config.daemonize, config.debug);
        return Ok(());
    }
    
    info!("Forking to background...");
    
    // First fork
    match unsafe { fork() }
        .map_err(|e| DaemonError::ForkFailed(format!("First fork failed: {}", e)))?
    {
        ForkResult::Parent { child } => {
            info!("Parent process exiting, child PID: {}", child);
            std::process::exit(0);
        }
        ForkResult::Child => {
            // Continue in child process
        }
    }
    
    // Create new session
    setsid()
        .map_err(|e| DaemonError::SessionCreationFailed(format!("Session creation failed: {}", e)))?;
    
    // Second fork to ensure we can't acquire controlling terminal
    match unsafe { fork() }
        .map_err(|e| DaemonError::ForkFailed(format!("Fork failed: {}", e)))?
    {
        ForkResult::Parent { child } => {
            info!("First child exiting, daemon PID: {}", child);
            std::process::exit(0);
        }
        ForkResult::Child => {
            // Continue in second child (actual daemon)
        }
    }
    
    // Redirect stdin/stdout/stderr to /dev/null unless in debug mode
    if !config.debug {
        let devnull = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?;
        
        let devnull_fd = devnull.as_raw_fd();
        
        dup2(devnull_fd, 0)?; // stdin
        dup2(devnull_fd, 1)?; // stdout
        dup2(devnull_fd, 2)?; // stderr
        
        info!("Redirected stdio to /dev/null");
    }
    
    info!("Daemonization complete, PID: {}", getpid());
    Ok(())
}

/// Drop privileges from root to specified user/group
///
/// Sequence (critical for security):
/// 1. Clear supplementary groups
/// 2. Set GID (must be before UID)
/// 3. Set UID (irreversible)
///
/// Only drops privileges if running as root.
///
/// # Arguments
///
/// * `config` - Privilege configuration with user/group
///
/// # Returns
///
/// Ok(()) if privileges dropped successfully or not root
pub fn drop_privileges(config: &PrivilegeConfig) -> Result<(), DaemonError> {
    // Only drop privileges if running as root
    if !getuid().is_root() {
        info!("Not running as root, skipping privilege drop");
        return Ok(());
    }
    
    if !config.drop_after_bind {
        info!("Privilege dropping disabled");
        return Ok(());
    }
    
    let username = config.user.as_ref()
        .ok_or_else(|| DaemonError::PrivilegeDropFailed(
            "No user specified for privilege drop".to_string()))?;
    
    let groupname = config.group.as_ref()
        .or(config.user.as_ref())
        .ok_or_else(|| DaemonError::PrivilegeDropFailed(
            "No group specified for privilege drop".to_string()))?;
    
    info!("Dropping privileges to {}:{}", username, groupname);
    
    // Look up user and group
    let user = User::from_name(username)
        .map_err(|e| DaemonError::PrivilegeDropFailed(
            format!("Failed to look up user: {}", e)
        ))?
        .ok_or_else(|| DaemonError::UserNotFound { 
            username: username.clone() 
        })?;
    
    let group = Group::from_name(groupname)
        .map_err(|e| DaemonError::PrivilegeDropFailed(
            format!("Failed to look up group: {}", e)
        ))?
        .ok_or_else(|| DaemonError::GroupNotFound { 
            groupname: groupname.clone() 
        })?;
    
    // Step 1: Clear supplementary groups
    setgroups(&[])
        .map_err(|e| DaemonError::PrivilegeDropFailed(
            format!("Failed to clear supplementary groups: {}", e)
        ))?;
    
    // Step 2: Set GID (must be before UID)
    setgid(group.gid)
        .map_err(|e| DaemonError::PrivilegeDropFailed(
            format!("Failed to set GID to {}: {}", group.gid, e)
        ))?;
    
    // Step 3: Set UID (irreversible)
    setuid(user.uid)
        .map_err(|e| DaemonError::PrivilegeDropFailed(
            format!("Failed to set UID to {}: {}", user.uid, e)
        ))?;
    
    info!("Successfully dropped privileges to {}:{} (UID={}, GID={})", 
          username, groupname, user.uid, group.gid);
    
    Ok(())
}

/// Create PID file with current process ID
///
/// Creates PID file atomically using O_EXCL flag to prevent races.
/// Changes ownership to target user if specified.
///
/// # Arguments
///
/// * `path` - Path to PID file
/// * `user` - Optional user to chown PID file to
///
/// # Returns
///
/// Ok(PidFile) handle that removes file on drop
pub fn create_pid_file(
    path: &Path,
    user: Option<&str>
) -> Result<PidFile, DaemonError> {
    info!("Creating PID file at {:?}", path);
    
    // Remove existing PID file if it exists
    if path.exists() {
        warn!("Removing existing PID file at {:?}", path);
        remove_file(path)
            .map_err(|e| DaemonError::PidFileError(
                format!("Failed to remove existing PID file {:?}: {}", path, e)
            ))?;
    }
    
    // Create PID file with O_EXCL for atomicity
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| DaemonError::PidFileError(
            format!("Failed to create PID file {:?}: {}", path, e)
        ))?;
    
    // Write current PID
    let pid = getpid();
    writeln!(file, "{}", pid)
        .map_err(|e| DaemonError::PidFileError(
            format!("Failed to write PID to file {:?}: {}", path, e)
        ))?;
    
    // Change ownership if user specified
    if let Some(username) = user {
        let user = User::from_name(username)?
            .ok_or_else(|| DaemonError::UserNotFound { 
                username: username.to_string() 
            })?;
        
        fchown(file.as_raw_fd(), Some(user.uid), Some(user.gid))?;
        
        info!("Changed PID file ownership to {}", username);
    }
    
    info!("Created PID file {:?} with PID {}", path, pid);
    
    Ok(PidFile {
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_daemon_config_default() {
        let config = DaemonConfig::default();
        assert!(!config.daemonize);
        assert!(!config.debug);
        assert!(config.pid_file.is_none());
    }
    
    #[test]
    fn test_privilege_config_default() {
        let config = PrivilegeConfig::default();
        assert!(config.user.is_none());
        assert!(config.group.is_none());
        assert!(config.drop_after_bind);
    }
    
    #[test]
    fn test_pid_file_creation() {
        let temp_dir = TempDir::new().unwrap();
        let pid_path = temp_dir.path().join("test.pid");
        
        let pid_file = create_pid_file(&pid_path, None).unwrap();
        assert!(pid_path.exists());
        
        // Verify PID was written
        let content = std::fs::read_to_string(&pid_path).unwrap();
        let pid: i32 = content.trim().parse().unwrap();
        assert_eq!(pid, getpid().as_raw());
        
        // PID file should be removed on drop
        drop(pid_file);
        assert!(!pid_path.exists());
    }
}
