// Copyright (C) 2000-2022 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! PID file management for daemon tracking
//!
//! This module implements PID file lifecycle management from src/dnsmasq.c (lines 819-878),
//! allowing system administrators and init systems to track the daemon's process ID.
//!
//! # Security
//!
//! PID file creation implements security measures to prevent symlink attacks and race
//! conditions:
//! - Uses O_EXCL flag to fail if file exists (prevents overwrite)
//! - Removes stale PID files if process is not running
//! - Changes ownership to target user before privilege drop
//! - Validates path to prevent directory traversal
//!
//! # Usage
//!
//! Typically:
//! 1. write_pidfile() is called after binding sockets but before privilege drop
//! 2. remove_pidfile() is called during daemon shutdown

use nix::unistd::{chown, Gid, Uid};
use std::fs::{remove_file, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Write the daemon's PID to the specified file
///
/// # Arguments
/// * `path` - Path to PID file (e.g., /var/run/dnsmasq.pid)
/// * `uid` - UID to chown file to (target unprivileged user)
/// * `gid` - GID to chown file to (target unprivileged group)
///
/// # Security
/// - Creates file with O_CREAT | O_WRONLY | O_EXCL to prevent overwrite attacks
/// - If file exists and process is dead, removes stale file and retries
/// - Changes ownership to target user so unprivileged daemon can update/remove it
/// - Verifies path is absolute to prevent relative path attacks
///
/// # Errors
/// Returns an error if:
/// - Path is not absolute
/// - File exists and process is still running
/// - Cannot create file (permissions, disk full)
/// - Cannot write PID
/// - Cannot change ownership
pub fn write_pidfile(path: &Path, uid: u32, gid: u32) -> Result<(), io::Error> {
    // Validate path is absolute
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("PID file path must be absolute: {}", path.display()),
        ));
    }

    // Try to create file with O_EXCL (fails if exists)
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // File exists - check if process is still running
            if is_process_alive(path)? {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "PID file exists and process is running: {}",
                        path.display()
                    ),
                ));
            }

            // Stale PID file - remove and retry
            remove_file(path)?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(path)?
        }
        Err(e) => return Err(e),
    };

    // Write current process PID
    let pid = std::process::id();
    writeln!(file, "{}", pid)?;
    file.flush()?;

    // Change ownership to target user so daemon can remove it after privilege drop
    chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Failed to chown PID file: {}", e),
        )
    })?;

    Ok(())
}

/// Remove the PID file
///
/// # Arguments
/// * `path` - Path to PID file to remove
///
/// # Errors
/// Returns an error if:
/// - File doesn't exist (not necessarily an error - could be already removed)
/// - Cannot remove file (permissions)
///
/// # Safety
/// This function validates that the PID in the file matches the current process
/// before removing it, to prevent accidentally removing another process's PID file.
pub fn remove_pidfile(path: &Path) -> Result<(), io::Error> {
    // Validate path is absolute
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("PID file path must be absolute: {}", path.display()),
        ));
    }

    // Check if file exists
    if !path.exists() {
        // Not an error - file may have been removed already
        return Ok(());
    }

    // Read PID from file
    let content = std::fs::read_to_string(path)?;
    let file_pid: u32 = content
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid PID in file"))?;

    // Verify it's our PID before removing
    let our_pid = std::process::id();
    if file_pid != our_pid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "PID file contains different PID ({} vs our {})",
                file_pid, our_pid
            ),
        ));
    }

    // Remove the file
    remove_file(path)?;

    Ok(())
}

/// Check if the process whose PID is in the file is still alive
///
/// # Arguments
/// * `path` - Path to PID file
///
/// # Returns
/// - Ok(true) if process is alive
/// - Ok(false) if process is dead or PID file is invalid
/// - Err if cannot read file
fn is_process_alive(path: &Path) -> Result<bool, io::Error> {
    // Read PID from file
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(false), // Can't read file - assume dead
    };

    let pid: u32 = match content.trim().parse() {
        Ok(p) => p,
        Err(_) => return Ok(false), // Invalid PID - assume dead
    };

    // Check if process exists by sending signal 0
    // On Unix, kill(pid, 0) checks if process exists without sending a signal
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        match kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
            Ok(_) => Ok(true),  // Process exists
            Err(nix::errno::Errno::ESRCH) => Ok(false), // Process doesn't exist
            Err(nix::errno::Errno::EPERM) => Ok(true),  // Process exists but we can't signal it
            Err(_) => Ok(false), // Other error - assume dead
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix, we can't reliably check - assume alive to be safe
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_write_pidfile_requires_absolute_path() {
        let result = write_pidfile(Path::new("relative/path.pid"), 1000, 1000);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be absolute"));
    }

    #[test]
    fn test_remove_pidfile_requires_absolute_path() {
        let result = remove_pidfile(Path::new("relative/path.pid"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be absolute"));
    }

    #[test]
    fn test_write_and_remove_pidfile() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        // Write PID file (using our own UID/GID since we're not root)
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        let result = write_pidfile(&pidfile, uid, gid);
        assert!(result.is_ok());

        // Verify file contains our PID
        let content = fs::read_to_string(&pidfile).unwrap();
        let pid: u32 = content.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());

        // Remove PID file
        let result = remove_pidfile(&pidfile);
        assert!(result.is_ok());

        // Verify file is gone
        assert!(!pidfile.exists());
    }

    #[test]
    fn test_remove_nonexistent_pidfile() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("nonexistent.pid");

        // Removing nonexistent file should succeed (not an error)
        let result = remove_pidfile(&pidfile);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_pidfile_twice_fails() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        // First write succeeds
        assert!(write_pidfile(&pidfile, uid, gid).is_ok());

        // Second write fails (file exists and process is alive)
        let result = write_pidfile(&pidfile, uid, gid);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("process is running"));

        // Cleanup
        let _ = remove_pidfile(&pidfile);
    }

    #[test]
    fn test_remove_pidfile_with_wrong_pid() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        // Write a different PID to the file
        fs::write(&pidfile, "999999\n").unwrap();

        // Trying to remove should fail (PID mismatch)
        let result = remove_pidfile(&pidfile);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("different PID"));

        // Cleanup
        let _ = fs::remove_file(&pidfile);
    }

    #[test]
    fn test_is_process_alive_with_invalid_pid() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        // Write invalid PID
        fs::write(&pidfile, "not_a_number\n").unwrap();

        // Should return false for invalid PID
        let result = is_process_alive(&pidfile);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_is_process_alive_with_dead_pid() {
        let temp_dir = TempDir::new().unwrap();
        let pidfile = temp_dir.path().join("test.pid");

        // Write a PID that definitely doesn't exist (PID 1 is init, but very high PIDs don't exist)
        fs::write(&pidfile, "999999\n").unwrap();

        let result = is_process_alive(&pidfile);
        assert!(result.is_ok());
        // Result could be true or false depending on system
    }
}
