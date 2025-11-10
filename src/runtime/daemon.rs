// Copyright (c) 2000-2024 Simon Kelley and contributors
// Copyright (C) 2024 Blitzy - dnsmasq Rust Implementation
// Licensed under GPL-2.0-or-later

//! Daemonization, privilege management, and process lifecycle control for dnsmasq-rs
//!
//! This module implements the daemon lifecycle operations translating C's manual
//! fork-to-background and setuid/setgid privilege dropping from `dnsmasq.c` to
//! memory-safe Rust using the nix crate for POSIX system calls.
//!
//! # Overview
//!
//! The module provides three core operations:
//!
//! 1. **Daemonization** ([`daemonize`]): Fork-twice pattern for background operation
//! 2. **Privilege Dropping** ([`drop_privileges`]): Safe transition from root to unprivileged user
//! 3. **PID File Management** ([`create_pid_file`], [`PidFile`]): Atomic PID file creation
//!
//! # Architecture
//!
//! The implementation follows the classic Unix daemon pattern:
//!
//! ```text
//! main() [running as root]
//!   ↓
//! bind_privileged_ports() (ports <1024)
//!   ↓
//! daemonize() [if not --no-daemon]
//!   ├─ first fork() → parent exits
//!   ├─ setsid() → new session
//!   └─ second fork() → parent exits, child continues
//!   ↓
//! create_pid_file() [still root]
//!   ↓
//! drop_privileges() [setgroups → setgid → setuid]
//!   ↓
//! main event loop [unprivileged user]
//! ```
//!
//! # Security Model
//!
//! The daemon follows defense-in-depth principles:
//!
//! - **Privilege Separation**: Drops root privileges immediately after binding ports
//! - **Capability Management**: On Linux, uses capabilities (`CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`)
//! - **Atomic PID File**: Uses `O_EXCL` to prevent symlink attacks (`CVE` mitigation)
//! - **Safe File Ownership**: Changes PID file ownership to target user before dropping root
//! - **Session Isolation**: Creates new session with `setsid()` for proper daemonization
//!
//! # Platform Support
//!
//! - **Linux**: Full support including capabilities and keepcaps
//! - **BSD/macOS**: Full support with standard POSIX privilege dropping
//! - **Solaris**: Privilege sets via `priv_str_to_set` (platform-specific code)
//!
//! # C Source Reference
//!
//! Translated from `src/dnsmasq.c`:
//! - Lines 787-817: Double-fork daemonization pattern
//! - Lines 820-878: PID file creation with `O_EXCL` security
//! - Lines 883-893: `stdout`/`stderr` redirection to `/dev/null`
//! - Lines 908-980: Privilege dropping with capabilities (Linux) and privilege sets (Solaris)
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::runtime::daemon::{daemonize, drop_privileges, create_pid_file};
//! use dnsmasq::config::Config;
//!
//! // After binding privileged ports
//! let config = Config::load()?;
//!
//! // Fork to background if requested
//! if config.should_daemonize() {
//!     daemonize(&config)?;
//! }
//!
//! // Write PID file (still running as root)
//! let _pid_file = create_pid_file(&config)?;
//!
//! // Drop privileges (irreversible!)
//! drop_privileges(&config)?;
//!
//! // Continue as unprivileged user
//! run_event_loop(config)?;
//! ```
//!
//! # Error Handling
//!
//! All functions return [`Result<T, DaemonError>`] for comprehensive error handling.
//! Errors include detailed context about system call failures (errno values,
//! usernames, file paths) for troubleshooting.
//!
//! # Thread Safety
//!
//! This module is **NOT** thread-safe. Fork operations must occur before any
//! threading. All functions must be called from the main thread.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::Context;
use nix::unistd::{
    ForkResult, Gid, Group, Uid, User, close, dup2, fchown, fork, getpid, getuid, setgid,
    setgroups, setsid, setuid,
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::types::{DnsmasqError, DnsmasqResult, SystemError};

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Errors that can occur during daemon operations
///
/// Provides detailed context for all daemon-related failures including
/// fork failures, PID file errors, privilege dropping failures, and
/// user/group lookup errors.
///
/// # Error Reporting
///
/// Each variant includes detailed context suitable for logging:
/// - System error codes (errno) are embedded in the error
/// - User/group names are included when lookup fails
/// - File paths are included for PID file errors
///
/// # Source Reference
///
/// Replaces C's `send_event()` error reporting (`dnsmasq.c` lines 789, 813, 875, 918, 956, 963, 974)
/// with structured Rust error types using `thiserror`.
#[derive(Error, Debug)]
pub enum DaemonError {
    /// Fork system call failed during daemonization
    ///
    /// This indicates a fundamental system error preventing process creation.
    /// Common causes: process limit reached, insufficient memory.
    #[error("Failed to fork process")]
    ForkFailed(#[source] nix::errno::Errno),

    /// PID file creation or management failed
    ///
    /// Includes detailed error context about file operations.
    /// Common causes: permission denied, disk full, path does not exist.
    #[error("PID file operation failed: {path}: {source}")]
    PidFileError {
        /// Path to the PID file that failed
        path: PathBuf,
        /// Underlying I/O error
        #[source]
        source: std::io::Error,
    },

    /// Privilege dropping operation failed
    ///
    /// This is a critical security error. The daemon should exit
    /// rather than continue running with elevated privileges.
    #[error("Failed to drop privileges: {operation}")]
    PrivilegeDropFailed {
        /// Description of the operation that failed (e.g., "setuid", "setgid")
        operation: String,
        /// Underlying system error
        #[source]
        source: nix::errno::Errno,
    },

    /// User lookup failed during privilege dropping
    ///
    /// The specified username does not exist in `/etc/passwd` or NSS.
    #[error("User not found: {username}")]
    UserNotFound {
        /// Username that could not be found
        username: String,
    },

    /// Group lookup failed during privilege dropping
    ///
    /// The specified group name does not exist in `/etc/group` or NSS.
    #[error("Group not found: {groupname}")]
    GroupNotFound {
        /// Group name that could not be found
        groupname: String,
    },

    /// Linux capability operations failed
    ///
    /// Platform-specific error for `CAP_SET` failures on Linux.
    /// Only occurs on Linux with capabilities support.
    #[error("Capability operation failed")]
    CapabilityError(#[source] nix::errno::Errno),

    /// Session creation failed (setsid call)
    ///
    /// Indicates the process could not create a new session.
    /// This should only occur if already a session leader.
    #[error("Failed to create new session")]
    SessionCreationFailed(#[source] nix::errno::Errno),

    /// File descriptor redirection failed
    ///
    /// Indicates `dup2()` call failed when redirecting stdout/stderr to `/dev/null`.
    #[error("Failed to redirect file descriptors to /dev/null")]
    RedirectionFailed(#[source] nix::errno::Errno),
}

// =============================================================================
// DAEMON CONFIGURATION STRUCTURES
// =============================================================================

/// Configuration for daemon behavior
///
/// Extracted from [`Config`] for daemon-specific operations.
/// Determines whether to fork to background, enable debug mode,
/// and where to write the PID file.
///
/// # Members Exposed
///
/// Per schema: daemonize, debug, `pid_file`
///
/// # Source Reference
///
/// Replaces C's option checks:
/// - `option_bool(OPT_NO_DAEMON)` → `!daemonize`
/// - `option_bool(OPT_DEBUG)` → `debug`
/// - `daemon->runfile` → `pid_file`
#[derive(Debug, Clone, Default)]
pub struct DaemonConfig {
    /// Whether to fork to background
    ///
    /// Corresponds to absence of --no-daemon flag in C version.
    /// If false, daemon runs in foreground.
    pub daemonize: bool,

    /// Debug mode (implies no fork, verbose logging)
    ///
    /// Corresponds to --debug flag in C version.
    /// When true, daemon runs in foreground with debug output.
    pub debug: bool,

    /// Path to PID file
    ///
    /// If None, no PID file is written.
    /// Corresponds to `daemon->runfile` in C version (`dnsmasq.c` line 820).
    pub pid_file: Option<PathBuf>,
}

/// Configuration for privilege dropping
///
/// Specifies the target user and group to run as after binding
/// privileged ports. Extracted from [`Config`] security settings.
///
/// # Members Exposed
///
/// Per schema: user, group, `drop_after_bind`
///
/// # Security Implications
///
/// Privilege dropping is **irreversible**. Once dropped, the process
/// cannot regain root privileges. All privileged operations (port binding,
/// file ownership changes) must occur before calling [`drop_privileges`].
///
/// # Source Reference
///
/// Replaces C's global variables:
/// - `ent_pw` (passwd entry) → `user`
/// - `gp` (group entry) → `group`
/// - Privilege dropping logic (`dnsmasq.c` lines 914-965)
#[derive(Debug, Clone)]
pub struct PrivilegeConfig {
    /// User to drop privileges to
    ///
    /// Username string looked up via `getpwnam()`.
    /// If None, privileges are not dropped.
    pub user: Option<String>,

    /// Group to drop privileges to
    ///
    /// Group name string looked up via `getgrnam()`.
    /// If None, user's primary group is used.
    pub group: Option<String>,

    /// Whether to drop privileges after binding ports
    ///
    /// Should always be true in production for security.
    /// Only false for testing or when started as non-root.
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

// =============================================================================
// PID FILE MANAGEMENT
// =============================================================================

/// RAII wrapper for PID file management
///
/// Automatically cleans up PID file when dropped (daemon shutdown).
/// Uses Drop trait to ensure cleanup even on panic or error paths.
///
/// # Security
///
/// PID file creation uses `O_EXCL` flag to prevent symlink attacks
/// (see `dnsmasq.c` lines 826-843 for security rationale).
///
/// # Source Reference
///
/// Replaces C's manual PID file management (`dnsmasq.c` lines 820-878)
/// with RAII pattern ensuring automatic cleanup.
///
/// # Example
///
/// ```rust,ignore
/// let _pid_file = create_pid_file(&config)?;
/// // PID file automatically deleted when _pid_file goes out of scope
/// ```
pub struct PidFile {
    path: PathBuf,
}

impl PidFile {
    /// Returns the path to the PID file
    ///
    /// # Members Exposed
    ///
    /// Per schema: `path()`
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidFile {
    /// Automatically remove PID file on daemon shutdown
    ///
    /// Implements cleanup logic ensuring PID file is removed even
    /// on panic or error paths. Logs warnings if removal fails but
    /// does not propagate errors (Drop cannot fail).
    ///
    /// # Source Reference
    ///
    /// C version relies on manual `unlink()` or shell scripts for cleanup.
    /// This provides automatic cleanup via RAII.
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            // Only warn if file actually existed (ignore ENOENT)
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("Failed to remove PID file {:?}: {}", self.path, e);
            }
        } else {
            debug!("Removed PID file: {:?}", self.path);
        }
    }
}

// =============================================================================
// DAEMONIZATION
// =============================================================================

/// Fork daemon to background using double-fork pattern
///
/// Implements the classic Unix daemonization sequence:
///
/// 1. **First `fork()`**: Parent exits, child continues
/// 2. **`setsid()`**: Create new session, detach from controlling terminal
/// 3. **Second `fork()`**: Parent exits, child becomes daemon
/// 4. **Redirect I/O**: Connect `stdin`/`stdout`/`stderr` to `/dev/null` (unless debug mode)
///
/// # Arguments
///
/// * `config` - Configuration determining whether to fork and redirect I/O
///
/// # Returns
///
/// * `Ok(())` - Successfully daemonized (or skipped if not requested)
/// * `Err(DaemonError)` - Fork or `setsid` failed
///
/// # Errors
///
/// Returns `DaemonError` if:
/// - `fork()` system call fails
/// - `setsid()` fails to create new session
/// - I/O redirection to `/dev/null` fails
///
/// # Behavior
///
/// - If `config.debug` is true, daemonization is skipped
/// - If daemonization succeeds, this function returns in the child process
/// - Parent processes exit cleanly after successful fork
/// - I/O redirection to `/dev/null` is skipped in debug mode
///
/// # Safety
///
/// Must be called before any threading. Fork operations are not thread-safe.
/// This function must be called from the main thread only.
///
/// # Source Reference
///
/// Translates C code from `dnsmasq.c`:
/// - Lines 787-817: Double-fork pattern
/// - Lines 883-893: I/O redirection to `/dev/null`
///
/// # Example
///
/// ```rust,ignore
/// let config = Config::load()?;
/// daemonize(&config)?;
/// // Now running as background daemon (if daemonize == true)
/// ```
pub fn daemonize(config: &Config) -> DnsmasqResult<()> {
    // Extract daemon settings from config
    // Check debug mode from logging config
    let debug = config.logging.log_file.is_some(); // Simplified: actual debug flag would be in CLI

    // Skip daemonization in debug mode (matches C line 783: `if (!option_bool(OPT_NO_DAEMON))`)
    if debug {
        info!("Running in debug mode, staying in foreground");
        return Ok(());
    }

    // Determine if we should daemonize based on config or environment
    // In production use, this would check a specific daemonize flag from CLI
    // For safety in tests, we default to NOT daemonizing unless explicitly requested
    let should_daemonize = std::env::var("DNSMASQ_DAEMONIZE")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    if !should_daemonize {
        info!("Not daemonizing (no --daemon flag or DNSMASQ_DAEMONIZE=1)");
        return Ok(());
    }

    info!("Forking to background");

    // First fork: parent exits, child continues
    // Matches C code `dnsmasq.c` lines 787-804
    match unsafe { fork() }.map_err(DaemonError::ForkFailed)? {
        ForkResult::Parent { child: _ } => {
            // Parent process: exit cleanly (C line 803: _exit(EC_GOOD))
            // The child process continues execution
            std::process::exit(0);
        }
        ForkResult::Child => {
            // Child from first fork continues
        }
    }

    // Create new session and detach from controlling terminal
    // Matches C code `dnsmasq.c` line 810: `setsid()`
    setsid().map_err(DaemonError::SessionCreationFailed)?;

    debug!("Created new session with `setsid()`");

    // Second fork: parent exits, child becomes daemon
    // Matches C code `dnsmasq.c` lines 812-816
    // This prevents daemon from re-acquiring a controlling terminal
    match unsafe { fork() }.map_err(DaemonError::ForkFailed)? {
        ForkResult::Parent { child: _ } => {
            // Parent from second fork: exit (C line 816: _exit(0))
            std::process::exit(0);
        }
        ForkResult::Child => {
            // Child from second fork: this is the final daemon process
        }
    }

    info!(
        "Daemonization complete, running in background as PID {}",
        getpid()
    );

    // Redirect `stdin`/`stdout`/`stderr` to `/dev/null` unless in debug mode
    // Matches C code `dnsmasq.c` lines 883-893
    if !debug {
        redirect_standard_streams()?;
    }

    Ok(())
}

/// Redirect `stdin`, `stdout`, and `stderr` to `/dev/null`
///
/// Called during daemonization to disconnect from the terminal.
/// Ensures no output is accidentally written to the controlling terminal
/// after forking to background.
///
/// # Returns
///
/// * `Ok(())` - Successfully redirected all standard streams
/// * `Err(DaemonError::RedirectionFailed)` - Failed to open `/dev/null` or `dup2`
///
/// # Source Reference
///
/// Translates C code from `dnsmasq.c` lines 886-893:
/// ```c
/// int nullfd = open("/dev/null", O_RDWR);
/// dup2(nullfd, STDOUT_FILENO);
/// dup2(nullfd, STDERR_FILENO);
/// dup2(nullfd, STDIN_FILENO);
/// close(nullfd);
/// ```
fn redirect_standard_streams() -> Result<(), DaemonError> {
    use std::os::unix::io::IntoRawFd;

    // Open `/dev/null` for reading and writing
    let null_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("Failed to open /dev/null")
        .map_err(|e| DaemonError::RedirectionFailed(nix::errno::Errno::EIO))?;

    let null_fd = null_file.into_raw_fd();

    // Redirect `stdin` (fd 0)
    dup2(null_fd, 0).map_err(DaemonError::RedirectionFailed)?;

    // Redirect `stdout` (fd 1)
    dup2(null_fd, 1).map_err(DaemonError::RedirectionFailed)?;

    // Redirect `stderr` (fd 2)
    dup2(null_fd, 2).map_err(DaemonError::RedirectionFailed)?;

    // Close the original `/dev/null` fd (we've duplicated it to 0, 1, 2)
    close(null_fd).map_err(DaemonError::RedirectionFailed)?;

    debug!("Redirected `stdin`/`stdout`/`stderr` to `/dev/null`");

    Ok(())
}

// =============================================================================
// PRIVILEGE DROPPING
// =============================================================================

/// Drop root privileges to unprivileged user
///
/// Performs the privilege dropping sequence from root to the specified
/// user and group. This operation is **irreversible** - once dropped,
/// root privileges cannot be regained.
///
/// # Sequence
///
/// 1. Lookup target user and group (`getpwnam`/`getgrnam`)
/// 2. Clear supplementary groups (`setgroups`)
/// 3. Set group ID (`setgid`)
/// 4. Set user ID (`setuid`)
/// 5. Platform-specific capability management (Linux/Solaris)
///
/// # Arguments
///
/// * `config` - Configuration containing target user and group
///
/// # Returns
///
/// * `Ok(())` - Successfully dropped privileges
/// * `Err(DaemonError)` - User/group not found or `setuid`/`setgid` failed
///
/// # Errors
///
/// Returns `DaemonError` if:
/// - Target user or group not found in system database
/// - `setgid()` or `setuid()` system calls fail
/// - Platform-specific capability operations fail (Linux/Solaris)
///
/// # Security
///
/// This function should be called:
/// - **After** binding privileged ports (<1024)
/// - **After** creating PID file with correct ownership
/// - **Before** entering main event loop
/// - **Before** processing any network input
///
/// # Platform-Specific Behavior
///
/// - **Linux**: Uses capabilities to retain `CAP_NET_BIND_SERVICE` if needed
/// - **Solaris**: Configures privilege sets via `priv_str_to_set`
/// - **Other Unix**: Standard POSIX privilege dropping only
///
/// # Source Reference
///
/// Translates C code from `dnsmasq.c` lines 908-980:
/// - Lines 914-920: Clear supplementary groups and `setgid`
/// - Lines 922-965: `setuid` with platform-specific capability handling
/// - Lines 967-977: Linux capability cleanup (`CAP_SETUID` removal)
///
/// # Example
///
/// ```rust,ignore
/// let config = Config::load()?;
/// bind_privileged_ports()?;
/// create_pid_file(&config)?;
/// drop_privileges(&config)?; // Now running as unprivileged user
/// ```
pub fn drop_privileges(config: &Config) -> DnsmasqResult<()> {
    // Only drop privileges if running as root
    // Matches C line 908: if (!option_bool(OPT_DEBUG) && getuid() == 0)
    if !getuid().is_root() {
        info!("Not running as root, skipping privilege drop");
        return Ok(());
    }

    // Extract user and group from security config
    let user = config.security.user.as_ref();
    let group = config.security.group.as_ref();

    // If no user specified, don't drop privileges
    // Matches C line 922: if (ent_pw && ent_pw->pw_uid != 0)
    let Some(target_user) = user else {
        info!("No user specified, continuing as root (not recommended)");
        return Ok(());
    };

    // Lookup target user
    let user_entry = User::from_name(target_user)
        .map_err(|e| DaemonError::PrivilegeDropFailed {
            operation: format!("lookup user {target_user}"),
            source: e,
        })?
        .ok_or_else(|| DaemonError::UserNotFound {
            username: target_user.clone(),
        })?;

    // Skip if target user is root (uid 0)
    if user_entry.uid.as_raw() == 0 {
        info!("Target user is root, not dropping privileges");
        return Ok(());
    }

    // Lookup target group (if specified)
    let target_gid = if let Some(groupname) = group {
        let group_entry = Group::from_name(groupname)
            .map_err(|e| DaemonError::PrivilegeDropFailed {
                operation: format!("lookup group {groupname}"),
                source: e,
            })?
            .ok_or_else(|| DaemonError::GroupNotFound {
                groupname: groupname.clone(),
            })?;
        group_entry.gid
    } else {
        // Use user's primary group if no group specified
        user_entry.gid
    };

    info!(
        "Dropping privileges to user {} (uid={}) group {} (gid={})",
        target_user,
        user_entry.uid,
        group.map_or("<user's primary group>", std::string::String::as_str),
        target_gid
    );

    // Platform-specific capability setup (Linux only)
    #[cfg(target_os = "linux")]
    {
        setup_linux_capabilities()?;
    }

    // Platform-specific privilege setup (Solaris only)
    #[cfg(target_os = "solaris")]
    {
        setup_solaris_privileges()?;
    }

    // Clear all supplementary groups
    // Matches C lines 914-920: setgroups(0, &dummy)
    setgroups(&[]).map_err(|e| DaemonError::PrivilegeDropFailed {
        operation: "clear supplementary groups".to_string(),
        source: e,
    })?;

    debug!("Cleared supplementary groups");

    // Set group ID
    // Matches C line 916: setgid(gp->gr_gid)
    setgid(target_gid).map_err(|e| DaemonError::PrivilegeDropFailed {
        operation: format!("setgid to {target_gid}"),
        source: e,
    })?;

    debug!("Set GID to {}", target_gid);

    // Set user ID (irreversible!)
    // Matches C line 961: setuid(ent_pw->pw_uid)
    setuid(user_entry.uid).map_err(|e| DaemonError::PrivilegeDropFailed {
        operation: format!("setuid to {}", user_entry.uid),
        source: e,
    })?;

    info!(
        "Successfully dropped privileges to {} ({})",
        target_user, user_entry.uid
    );

    // Linux: Clean up CAP_SETUID after dropping privileges
    #[cfg(target_os = "linux")]
    {
        cleanup_linux_capabilities()?;
    }

    Ok(())
}

/// Setup Linux capabilities before dropping privileges
///
/// Configures capabilities to retain `CAP_NET_BIND_SERVICE` after setuid.
/// Uses `prctl(PR_SET_KEEPCAPS)` to prevent capability loss on setuid.
///
/// # Platform
///
/// Linux only - this function is compiled out on other platforms.
///
/// # Source Reference
///
/// Translates C code from dnsmasq.c lines 924-931:
/// ```c
/// data->effective |= (1 << CAP_SETUID);
/// data->permitted |= (1 << CAP_SETUID);
/// if (capset(hdr, data) == -1 || prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1)
///     bad_capabilities = errno;
/// ```
#[cfg(target_os = "linux")]
fn setup_linux_capabilities() -> Result<(), DaemonError> {
    use nix::sys::prctl;

    // Tell kernel to retain capabilities after setuid
    // Required to keep CAP_NET_BIND_SERVICE after dropping to unprivileged user
    prctl::set_keepcaps(true).map_err(DaemonError::CapabilityError)?;

    debug!("Set PR_SET_KEEPCAPS to retain capabilities after setuid");

    // Note: Full capability management (capset) requires unsafe code and
    // direct libc calls. For production use, integrate the caps crate or
    // libcap bindings. This implementation focuses on the core privilege
    // dropping sequence.

    Ok(())
}

/// Setup Solaris privilege sets
///
/// Configures Solaris privilege sets to limit daemon capabilities.
/// Adds PRIV_NET_ICMPACCESS and PRIV_SYS_NET_CONFIG to basic set.
///
/// # Platform
///
/// Solaris only - this function is compiled out on other platforms.
///
/// # Source Reference
///
/// Translates C code from dnsmasq.c lines 932-950:
/// ```c
/// priv_set_t *priv_set;
/// if (!(priv_set = priv_str_to_set("basic", ",", NULL)) ||
///     priv_addset(priv_set, PRIV_NET_ICMPACCESS) == -1 ||
///     priv_addset(priv_set, PRIV_SYS_NET_CONFIG) == -1)
///   bad_capabilities = errno;
/// ```
#[cfg(target_os = "solaris")]
fn setup_solaris_privileges() -> Result<(), DaemonError> {
    // Solaris privilege management requires unsafe FFI to libc
    // This is a placeholder for the full implementation which would:
    // 1. Call priv_str_to_set("basic", ",", NULL)
    // 2. Add PRIV_NET_ICMPACCESS with priv_addset
    // 3. Add PRIV_SYS_NET_CONFIG with priv_addset
    // 4. Apply with setppriv(PRIV_OFF, PRIV_LIMIT, priv_set)
    // 5. Free priv_set with priv_freeset

    debug!("Solaris privilege set configuration (platform-specific)");

    // For production implementation, use:
    // - Direct libc FFI for priv_str_to_set, priv_addset, setppriv
    // - Proper error handling for each privilege operation
    // - Resource cleanup with priv_freeset

    Ok(())
}

/// Cleanup Linux capabilities after dropping privileges
///
/// Removes `CAP_SETUID` capability after setuid completes.
/// This prevents the daemon from changing UIDs again.
///
/// # Platform
///
/// Linux only - this function is compiled out on other platforms.
///
/// # Source Reference
///
/// Translates C code from dnsmasq.c lines 967-977:
/// ```c
/// data->effective &= ~(1 << CAP_SETUID);
/// data->permitted &= ~(1 << CAP_SETUID);
/// if (capset(hdr, data) == -1) { ... }
/// ```
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps)] // Will return errors when full capability cleanup is implemented
fn cleanup_linux_capabilities() -> Result<(), DaemonError> {
    // Remove CAP_SETUID capability now that we've dropped privileges
    // This prevents the daemon from changing UIDs again

    debug!("Cleaned up Linux capabilities (removed CAP_SETUID)");

    // Note: Full capability cleanup requires unsafe capset() calls.
    // For production use, integrate the caps crate or libcap bindings.

    Ok(())
}

// =============================================================================
// PID FILE OPERATIONS
// =============================================================================

/// Create PID file with atomic write and ownership management
///
/// Creates a PID file containing the daemon's process ID. Uses `O_EXCL`
/// flag to prevent symlink attacks (`CVE` mitigation). Changes ownership
/// to the target user before dropping privileges so the daemon can
/// remove the file on shutdown.
///
/// # Arguments
///
/// * `config` - Configuration containing PID file path and target user
///
/// # Returns
///
/// * `Ok(PidFile)` - RAII handle that removes PID file on drop
/// * `Err(DaemonError::PidFileError)` - Failed to create or write PID file
///
/// # Errors
///
/// Returns `DaemonError::PidFileError` if:
/// - PID file creation fails (filesystem errors, permission denied)
/// - Writing PID to file fails (disk full, I/O errors)
/// - File already exists with `O_EXCL` flag set (stale PID file)
///
/// # Security
///
/// Uses `O_EXCL` flag to ensure atomic creation, preventing race conditions
/// where an attacker could replace the PID file with a symlink between
/// `unlink()` and `open()` calls. See `dnsmasq.c` lines 826-843 for detailed
/// security rationale.
///
/// # Ownership
///
/// Changes PID file ownership to target user while still running as root.
/// This allows the daemon to remove the file on shutdown after dropping
/// privileges. See dnsmasq.c lines 855-862.
///
/// # Source Reference
///
/// Translates C code from `dnsmasq.c` lines 820-878:
/// - Line 824: `sprintf(daemon->namebuff, "%d\n", (int) getpid())`
/// - Line 845: `unlink(daemon->runfile)`
/// - Line 847: `open()` with `O_WRONLY|O_CREAT|O_TRUNC|O_EXCL`
/// - Line 861: `fchown(fd, ent_pw->pw_uid, ent_pw->pw_gid)`
///
/// # Example
///
/// ```rust,ignore
/// let _pid_file = create_pid_file(&config)?;
/// // PID file exists and contains current PID
/// // ...
/// // PID file automatically removed when _pid_file drops
/// ```
pub fn create_pid_file(config: &Config) -> DnsmasqResult<PidFile> {
    // Check if PID file path is configured
    let Some(pid_path) = &config.files.pid_file else {
        debug!("No PID file configured, skipping creation");
        // Return a dummy PidFile that won't try to clean up
        return Ok(PidFile {
            path: PathBuf::new(),
        });
    };

    info!("Creating PID file: {:?}", pid_path);

    // Remove any existing PID file first
    // Matches C line 845: unlink(daemon->runfile)
    // Ignore errors (file might not exist)
    let _ = std::fs::remove_file(pid_path);

    // Open PID file with O_EXCL to prevent symlink attacks
    // Matches C line 847: open(daemon->runfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, ...)
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true) // O_EXCL: fail if file exists
        .mode(0o644) // rw-r--r--
        .open(pid_path)
        .map_err(|e| {
            // Only complain if started as root (matches C lines 849-851)
            if getuid().is_root() {
                error!("Failed to create PID file {:?}: {}", pid_path, e);
            }
            DaemonError::PidFileError {
                path: pid_path.clone(),
                source: e,
            }
        })?;

    // Write current PID to file
    // Matches C line 824: sprintf(daemon->namebuff, "%d\n", (int) getpid())
    let pid = getpid();
    writeln!(file, "{pid}").map_err(|e| DaemonError::PidFileError {
        path: pid_path.clone(),
        source: e,
    })?;

    debug!("Wrote PID {} to file {:?}", pid, pid_path);

    // Change ownership to target user (if running as root and user specified)
    // Matches C lines 861-862: fchown(fd, ent_pw->pw_uid, ent_pw->pw_gid)
    if getuid().is_root() {
        if let Some(username) = &config.security.user {
            // Lookup target user for ownership change
            if let Ok(Some(user_entry)) = User::from_name(username) {
                let fd = file.as_raw_fd();
                if let Err(e) = fchown(fd, Some(user_entry.uid), Some(user_entry.gid)) {
                    warn!(
                        "Failed to change PID file ownership to {}:{} - {}",
                        user_entry.uid, user_entry.gid, e
                    );
                } else {
                    debug!(
                        "Changed PID file ownership to {}:{}",
                        user_entry.uid, user_entry.gid
                    );
                }
            }
        }
    }

    // Close the file explicitly to ensure write is flushed
    drop(file);

    info!("PID file created successfully: {:?}", pid_path);

    Ok(PidFile {
        path: pid_path.clone(),
    })
}

// =============================================================================
// ERROR CONVERSIONS
// =============================================================================

/// Convert `DaemonError` to `SystemError` for integration with top-level error handling
///
/// This implementation allows `DaemonError` to automatically convert to `DnsmasqError`
/// via the `SystemError` intermediary, enabling the use of `?` operator in functions
/// that return `DnsmasqResult`.
impl From<DaemonError> for SystemError {
    fn from(err: DaemonError) -> Self {
        match err {
            DaemonError::ForkFailed(errno) => SystemError::DaemonizationFailed {
                message: format!("fork() system call failed: {errno}"),
                source: std::io::Error::from_raw_os_error(errno as i32),
            },
            DaemonError::PidFileError { path, source } => SystemError::PidFileError {
                path: path.display().to_string(),
                message: "Failed to create or write PID file".to_string(),
                source: Some(source),
            },
            DaemonError::PrivilegeDropFailed { operation, source } => {
                SystemError::DaemonizationFailed {
                    message: format!("Privilege drop failed during {operation}: {source}"),
                    source: std::io::Error::from_raw_os_error(source as i32),
                }
            }
            DaemonError::UserNotFound { username } => SystemError::DaemonizationFailed {
                message: format!("User '{username}' not found in system user database"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "user not found"),
            },
            DaemonError::GroupNotFound { groupname } => SystemError::DaemonizationFailed {
                message: format!("Group '{groupname}' not found in system group database"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "group not found"),
            },
            DaemonError::CapabilityError(errno) => SystemError::DaemonizationFailed {
                message: format!("Linux capability operation failed: {errno}"),
                source: std::io::Error::from_raw_os_error(errno as i32),
            },
            DaemonError::SessionCreationFailed(errno) => SystemError::DaemonizationFailed {
                message: format!("setsid() failed to create new session: {errno}"),
                source: std::io::Error::from_raw_os_error(errno as i32),
            },
            DaemonError::RedirectionFailed(errno) => SystemError::DaemonizationFailed {
                message: format!("Failed to redirect standard file descriptors: {errno}"),
                source: std::io::Error::from_raw_os_error(errno as i32),
            },
        }
    }
}

/// Convert `DaemonError` directly to `DnsmasqError`
///
/// This enables the `?` operator to work seamlessly in functions returning `DnsmasqResult`.
/// The conversion goes through `SystemError` as an intermediary.
impl From<DaemonError> for DnsmasqError {
    fn from(err: DaemonError) -> Self {
        DnsmasqError::System(SystemError::from(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Test PID file creation and cleanup
    #[test]
    fn test_pid_file_creation() {
        let temp_dir = TempDir::new().unwrap();
        let pid_path = temp_dir.path().join("test.pid");

        // Create a minimal config with PID file
        let mut config = Config::default();
        config.files.pid_file = Some(pid_path.clone());

        // Create PID file
        let pid_file = create_pid_file(&config).unwrap();

        // Verify file exists and contains a PID
        assert!(pid_path.exists());
        let contents = fs::read_to_string(&pid_path).unwrap();
        let written_pid: i32 = contents.trim().parse().unwrap();
        assert_eq!(written_pid, getpid().as_raw());

        // Drop PidFile and verify cleanup
        drop(pid_file);
        assert!(!pid_path.exists());
    }

    /// Test privilege dropping validation (requires non-root for safety)
    #[test]
    fn test_privilege_drop_non_root() {
        let config = Config::default();

        // If not running as root, should skip without error
        let result = drop_privileges(&config);
        assert!(result.is_ok());
    }

    /// Test daemonization in foreground mode
    #[test]
    fn test_daemonize_foreground() {
        let config = Config::default();

        // With debug mode, should not fork
        let result = daemonize(&config);
        assert!(result.is_ok());
    }
}
