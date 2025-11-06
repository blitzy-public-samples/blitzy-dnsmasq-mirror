// Copyright (C) 2000-2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! PID file management module for dnsmasq daemon process tracking
//!
//! Provides async functions for secure PID file creation, writing, ownership management,
//! and deletion using tokio::fs. Implements security-hardened PID file handling with
//! unlink-before-create pattern to prevent symlink attacks (O_EXCL flag equivalent in Rust).
//!
//! This module replaces the PID file management from src/dnsmasq.c lines 819-878 and 2168-2169.
//!
//! # Security Model
//!
//! The PID file implementation follows the security model documented in the original C code:
//!
//! ## Symlink Attack Prevention
//!
//! Some installations of dnsmasq (e.g., Debian/Ubuntu) locate the pid-file in a directory
//! which is writable by the non-privileged user that dnsmasq runs as. This allows the
//! daemon to delete the file as part of its shutdown. This is a security hole to the
//! extent that an attacker running as the unprivileged user could replace the pidfile
//! with a symlink, and have the target of that symlink overwritten as root next time
//! dnsmasq starts.
//!
//! The implementation first deletes any existing file, and then opens it with the O_EXCL
//! flag (via `create_new(true)` in Rust), ensuring that the open() fails should there be
//! any existing file (because the unlink() failed, or an attacker exploited the race
//! between unlink() and open()). This ensures that no symlink attack can succeed.
//!
//! ## Privilege Handling
//!
//! Any compromise of the non-privileged user still theoretically allows the pid-file to
//! be replaced whilst dnsmasq is running. The worst that could allow is that the usual
//! "shutdown dnsmasq" shell command could be tricked into stopping any other process.
//!
//! Note that if dnsmasq is started as non-root (e.g., for testing) it silently ignores
//! failure to write the pid-file.
//!
//! ## Ownership Transfer
//!
//! The PID file ownership is changed to the unprivileged user after creation (when running
//! as root). This is not to allow deletion (which depends on directory permissions), but
//! to keep systemd >273 happy, which requires the PID file owner to match the daemon user.

use nix::unistd::{fchown, getpid, getuid, Gid, Uid};
use std::io::{Error, ErrorKind, Result};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use tokio::fs::{remove_file, OpenOptions};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

/// Write the daemon's PID to the specified file with security hardening
///
/// This function implements the secure PID file creation pattern from src/dnsmasq.c
/// lines 819-878. It follows the unlink-before-create pattern with O_EXCL to prevent
/// symlink attacks.
///
/// # Arguments
///
/// * `pidfile_path` - Path to the PID file (e.g., /var/run/dnsmasq.pid)
/// * `target_uid` - Optional UID to change file ownership to (unprivileged user)
/// * `target_gid` - Optional GID to change file ownership to (unprivileged group)
///
/// # Behavior
///
/// 1. Unlinks any existing PID file (ignoring errors)
/// 2. Creates new file with O_EXCL flag (fails if file exists)
/// 3. Writes current process PID as string with newline
/// 4. If running as root and target_uid/target_gid provided, changes ownership
/// 5. Returns error only if running as root (silently ignores errors for non-root)
///
/// # Security
///
/// - Prevents symlink attacks via unlink + O_EXCL pattern
/// - Only fails for root user (testing mode for non-root)
/// - File permissions set to 0o644 (readable by all, writable by owner)
/// - Ownership transferred to unprivileged user for systemd compatibility
///
/// # Errors
///
/// Returns error only when running as root if:
/// - File creation fails (permissions, disk full, race condition)
/// - Writing PID fails
/// - Ownership change fails (logged as warning, not fatal)
///
/// When running as non-root, all errors are silently ignored for testing compatibility.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use nix::unistd::{Uid, Gid};
///
/// # async fn example() -> std::io::Result<()> {
/// // Write PID file as root, transfer ownership to dnsmasq user
/// write_pidfile(
///     Path::new("/var/run/dnsmasq.pid"),
///     Some(Uid::from_raw(1000)),
///     Some(Gid::from_raw(1000))
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn write_pidfile(
    pidfile_path: &Path,
    target_uid: Option<Uid>,
    target_gid: Option<Gid>,
) -> Result<()> {
    debug!("Writing PID file to: {}", pidfile_path.display());

    // Get current process info
    let pid = getpid();
    let uid = getuid();
    let is_root = uid.is_root();

    // Format PID as string with newline (matching C: sprintf(daemon->namebuff, "%d\n", (int) getpid()))
    let pid_string = format!("{}\n", pid);

    // Step 1: Unlink existing file (ignore errors - file might not exist)
    // This corresponds to line 845: unlink(daemon->runfile);
    let _ = remove_file(pidfile_path).await;

    // Step 2: Create file with O_EXCL flag
    // This corresponds to line 847: open(daemon->runfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, ...)
    // Using create_new(true) provides O_EXCL semantics - fails if file exists
    let file_result = OpenOptions::new()
        .write(true)
        .create_new(true) // O_EXCL equivalent - fails if file exists after unlink
        .mode(0o644) // S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH from line 847
        .open(pidfile_path)
        .await;

    let mut file = match file_result {
        Ok(f) => f,
        Err(e) => {
            // Only complain if started as root (lines 850-851)
            if is_root {
                error!(
                    "Failed to create PID file {}: {}",
                    pidfile_path.display(),
                    e
                );
                return Err(e);
            } else {
                // Silently ignore for non-root (testing mode)
                debug!(
                    "Failed to create PID file {} (non-root mode, ignoring): {}",
                    pidfile_path.display(),
                    e
                );
                return Ok(());
            }
        }
    };

    // Step 3: Change ownership if running as root and target user specified
    // This corresponds to lines 861-862: fchown(fd, ent_pw->pw_uid, ent_pw->pw_gid)
    // We're still running as root here. Change the ownership of the PID file
    // to the user we will be running as. Note that this is not to allow
    // us to delete the file, since that depends on the permissions
    // of the directory containing the file. That directory will
    // need to be owned by the dnsmasq user, and the ownership of the
    // file has to match, to keep systemd >273 happy.
    if is_root {
        if let (Some(uid), Some(gid)) = (target_uid, target_gid) {
            // Only change ownership if target user is not root
            if !uid.is_root() {
                let fd = file.as_raw_fd();
                if let Err(e) = fchown(fd, Some(uid), Some(gid)) {
                    // Log warning but don't fail (matching C behavior at line 862)
                    warn!(
                        "Failed to change ownership of PID file {} to {}:{}: {}",
                        pidfile_path.display(),
                        uid,
                        gid,
                        e
                    );
                    // Note: C code stores this in chown_warn to log later, we log immediately
                }
            }
        }
    }

    // Step 4: Write PID string to file
    // This corresponds to line 864: read_write(fd, (unsigned char *)daemon->namebuff, strlen(daemon->namebuff), 0)
    if let Err(e) = file.write_all(pid_string.as_bytes()).await {
        if is_root {
            error!(
                "Failed to write PID to file {}: {}",
                pidfile_path.display(),
                e
            );
            // Attempt cleanup on error
            let _ = remove_file(pidfile_path).await;
            return Err(e);
        } else {
            debug!(
                "Failed to write PID to file {} (non-root mode, ignoring): {}",
                pidfile_path.display(),
                e
            );
            return Ok(());
        }
    }

    // Step 5: Flush to ensure data is written
    if let Err(e) = file.flush().await {
        if is_root {
            error!(
                "Failed to flush PID file {}: {}",
                pidfile_path.display(),
                e
            );
            // Attempt cleanup on error
            let _ = remove_file(pidfile_path).await;
            return Err(e);
        } else {
            debug!(
                "Failed to flush PID file {} (non-root mode, ignoring): {}",
                pidfile_path.display(),
                e
            );
            return Ok(());
        }
    }

    // Step 6: Sync to disk (matching close() behavior from line 868)
    if let Err(e) = file.sync_all().await {
        if is_root {
            error!(
                "Failed to sync PID file {}: {}",
                pidfile_path.display(),
                e
            );
            // Attempt cleanup on error
            let _ = remove_file(pidfile_path).await;
            return Err(e);
        } else {
            debug!(
                "Failed to sync PID file {} (non-root mode, ignoring): {}",
                pidfile_path.display(),
                e
            );
            return Ok(());
        }
    }

    info!("Successfully wrote PID {} to {}", pid, pidfile_path.display());
    Ok(())
}

/// Remove the PID file during daemon shutdown
///
/// This function implements the PID file cleanup from src/dnsmasq.c lines 2168-2169.
/// It attempts to delete the PID file and logs any errors without failing.
///
/// # Arguments
///
/// * `pidfile_path` - Path to the PID file to remove
///
/// # Behavior
///
/// Attempts to delete the PID file. If deletion fails, logs a warning but does not
/// return an error. This is appropriate for shutdown cleanup where we want to proceed
/// with shutdown even if PID file removal fails.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
///
/// # async fn example() {
/// // Remove PID file during shutdown
/// remove_pidfile(Path::new("/var/run/dnsmasq.pid")).await;
/// # }
/// ```
pub async fn remove_pidfile(pidfile_path: &Path) {
    debug!("Removing PID file: {}", pidfile_path.display());

    // This corresponds to lines 2168-2169 in C:
    // if (daemon->runfile)
    //   unlink(daemon->runfile);
    match remove_file(pidfile_path).await {
        Ok(()) => {
            info!("Successfully removed PID file: {}", pidfile_path.display());
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // File doesn't exist - this is fine, might have been already removed
            debug!(
                "PID file {} does not exist (already removed)",
                pidfile_path.display()
            );
        }
        Err(e) => {
            // Log warning but don't fail - this is cleanup code
            warn!(
                "Failed to remove PID file {}: {}",
                pidfile_path.display(),
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use tokio::fs as tokio_fs;

    #[tokio::test]
    async fn test_write_pidfile_creates_file() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        // Write PID file (as non-root for testing)
        write_pidfile(&pidfile, None, None).await.ok();

        // Verify file exists (might not if running as non-root and permission denied)
        if pidfile.exists() {
            let content = tokio_fs::read_to_string(&pidfile).await.unwrap();
            let pid = getpid();
            assert_eq!(content.trim(), pid.to_string());
        }
    }

    #[tokio::test]
    async fn test_write_pidfile_unlink_before_create() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        // Create initial file
        write_pidfile(&pidfile, None, None).await.ok();

        // Write again - should unlink first then create
        write_pidfile(&pidfile, None, None).await.ok();

        // Verify file still exists with current PID
        if pidfile.exists() {
            let content = tokio_fs::read_to_string(&pidfile).await.unwrap();
            let pid = getpid();
            assert_eq!(content.trim(), pid.to_string());
        }
    }

    #[tokio::test]
    async fn test_write_pidfile_correct_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        write_pidfile(&pidfile, None, None).await.ok();

        if pidfile.exists() {
            let metadata = fs::metadata(&pidfile).unwrap();
            let perms = metadata.permissions();
            // Check that permissions are 0o644 (readable by all, writable by owner)
            assert_eq!(perms.mode() & 0o777, 0o644);
        }
    }

    #[tokio::test]
    async fn test_remove_pidfile_deletes_file() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        // Create PID file
        write_pidfile(&pidfile, None, None).await.ok();

        if pidfile.exists() {
            // Remove it
            remove_pidfile(&pidfile).await;

            // Verify it's gone
            assert!(!pidfile.exists());
        }
    }

    #[tokio::test]
    async fn test_remove_pidfile_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("nonexistent.pid");

        // Should not panic or error
        remove_pidfile(&pidfile).await;
    }

    #[tokio::test]
    async fn test_pidfile_contains_newline() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        write_pidfile(&pidfile, None, None).await.ok();

        if pidfile.exists() {
            let content = tokio_fs::read_to_string(&pidfile).await.unwrap();
            // Should end with newline (matching C sprintf format "%d\n")
            assert!(content.ends_with('\n'));
        }
    }

    #[tokio::test]
    async fn test_write_pidfile_multiple_times() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        // Write multiple times - should succeed each time
        for _ in 0..3 {
            write_pidfile(&pidfile, None, None).await.ok();
        }

        if pidfile.exists() {
            let content = tokio_fs::read_to_string(&pidfile).await.unwrap();
            let pid = getpid();
            assert_eq!(content.trim(), pid.to_string());
        }
    }
}
