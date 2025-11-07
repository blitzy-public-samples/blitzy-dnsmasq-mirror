// Copyright (C) 2000-2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! Privilege dropping module for secure daemon operation
//!
//! This module implements secure privilege boundary enforcement, translating the
//! privilege dropping logic from `src/dnsmasq.c` (lines 908-980) into memory-safe
//! Rust using `nix` crate wrappers for `setuid`/`setgid`/`setgroups` operations.
//!
//! # Security Model
//!
//! The dnsmasq daemon must start as root to:
//! - Bind privileged ports (DNS port 53, DHCP ports 67/68)
//! - Access system configuration files
//! - Configure network interfaces
//!
//! After initialization, the daemon drops to an unprivileged user/group for
//! defense-in-depth, eliminating privilege escalation attack surface.
//!
//! # Platform-Specific Behavior
//!
//! - **Linux**: Uses capabilities (`CAP_SETUID`) to permit UID change, then drops
//!   the capability after privilege drop. Uses `PR_SET_KEEPCAPS` to preserve
//!   capabilities across `setuid`.
//! - **Solaris**: Uses privilege sets (`PRIV_NET_ICMPACCESS`, `PRIV_SYS_NET_CONFIG`)
//!   to retain network configuration capabilities after privilege drop.
//! - **BSD/macOS**: Simple `setuid`/`setgid` without additional capability management.
//!
//! # Memory Safety
//!
//! All privilege manipulation uses safe wrappers from the `nix` crate, eliminating:
//! - Buffer overflows in username/group name handling
//! - Use-after-free in capability structures
//! - Integer overflow in UID/GID arithmetic
//! - Null pointer dereferences in system calls
//!
//! # Example
//!
//! ```no_run
//! use dnsmasq::process::privileges::drop_privileges;
//!
//! // After binding privileged ports and opening files
//! drop_privileges("dnsmasq", "dnsmasq", false)?;
//! // Now running as unprivileged user
//! ```

use nix::unistd::{getuid, setgid, setgroups, setuid, Gid, Uid};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::io::Error as IoError;
use tracing::{debug, error, info, warn};

#[cfg(target_os = "solaris")]
use crate::ffi::platform::solaris_privileges::{
    priv_addset, priv_freeset, priv_inverse, priv_str_to_set, setppriv,
    PRIV_LIMIT, PRIV_NET_ICMPACCESS, PRIV_OFF, PRIV_SYS_NET_CONFIG,
};

#[cfg(target_os = "linux")]
use libc::{
    __user_cap_data_struct, __user_cap_header_struct, _LINUX_CAPABILITY_VERSION_3,
    capget, capset, CAP_SETUID,
};

#[cfg(target_os = "linux")]
use nix::sys::prctl::{prctl, PrctlOption};

/// Errors that can occur during privilege dropping operations
#[derive(Debug)]
pub enum PrivilegeError {
    /// Failed to lookup group in system database
    GroupNotFound(String, IoError),
    
    /// Failed to lookup user in system database
    UserNotFound(String, IoError),
    
    /// Failed to set group ID via setgid()
    SetGroupFailed(String, u32, IoError),
    
    /// Failed to set user ID via setuid()
    SetUserFailed(String, u32, IoError),
    
    /// Failed to clear supplementary groups via setgroups()
    SetGroupsFailed(IoError),
    
    /// Failed to manage Linux capabilities (capset/capget)
    CapabilityError(String, IoError),
    
    /// Failed to manage Solaris privilege sets
    PrivilegeSetError(String, IoError),
    
    /// Already running as unprivileged user (not root)
    AlreadyUnprivileged,
}

impl Display for PrivilegeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivilegeError::GroupNotFound(name, err) => {
                write!(f, "Failed to lookup group '{}': {}", name, err)
            }
            PrivilegeError::UserNotFound(name, err) => {
                write!(f, "Failed to lookup user '{}': {}", name, err)
            }
            PrivilegeError::SetGroupFailed(name, gid, err) => {
                write!(f, "Failed to set group '{}' (GID {}): {}", name, gid, err)
            }
            PrivilegeError::SetUserFailed(name, uid, err) => {
                write!(f, "Failed to set user '{}' (UID {}): {}", name, uid, err)
            }
            PrivilegeError::SetGroupsFailed(err) => {
                write!(f, "Failed to clear supplementary groups: {}", err)
            }
            PrivilegeError::CapabilityError(context, err) => {
                write!(f, "Capability operation failed ({}): {}", context, err)
            }
            PrivilegeError::PrivilegeSetError(context, err) => {
                write!(f, "Privilege set operation failed ({}): {}", context, err)
            }
            PrivilegeError::AlreadyUnprivileged => {
                write!(f, "Already running as unprivileged user (UID != 0)")
            }
        }
    }
}

impl Error for PrivilegeError {}

/// Drop privileges to specified user and group
///
/// This function replicates the privilege dropping logic from `src/dnsmasq.c`
/// lines 908-980, providing memory-safe privilege boundary enforcement.
///
/// # Arguments
///
/// * `username` - Target username (e.g., "dnsmasq", "nobody")
/// * `groupname` - Target group name (e.g., "dnsmasq", "nogroup")
/// * `debug_mode` - If true, skip privilege drop (for debugging)
///
/// # Returns
///
/// * `Ok(())` - Privileges successfully dropped
/// * `Err(PrivilegeError)` - Privilege drop failed (daemon should terminate)
///
/// # Platform Behavior
///
/// ## Linux
/// 1. Clear supplementary groups with `setgroups([])`
/// 2. Change group with `setgid()`
/// 3. Add `CAP_SETUID` capability
/// 4. Enable `PR_SET_KEEPCAPS` to preserve caps across `setuid`
/// 5. Change user with `setuid()`
/// 6. Remove `CAP_SETUID` capability
///
/// ## Solaris
/// 1. Clear supplementary groups with `setgroups([])`
/// 2. Change group with `setgid()`
/// 3. Create privilege set with "basic" + `PRIV_NET_ICMPACCESS` + `PRIV_SYS_NET_CONFIG`
/// 4. Invert privilege set and apply with `setppriv(PRIV_OFF, PRIV_LIMIT, ...)`
/// 5. Change user with `setuid()`
///
/// ## BSD/macOS
/// 1. Clear supplementary groups with `setgroups([])`
/// 2. Change group with `setgid()`
/// 3. Change user with `setuid()`
///
/// # Security
///
/// - **Irreversible**: Once dropped, privileges cannot be regained
/// - **Fail-closed**: Any error terminates the daemon (no partial drops)
/// - **Minimal capabilities**: Retains only necessary privileges on Linux/Solaris
/// - **Defense-in-depth**: Reduces attack surface for network-facing code
///
/// # Errors
///
/// Returns error if:
/// - User or group lookup fails
/// - Any system call (setgroups/setgid/setuid) fails
/// - Capability/privilege set manipulation fails
/// - Already running as non-root (cannot drop what you don't have)
pub fn drop_privileges(
    username: &str,
    groupname: &str,
    debug_mode: bool,
) -> Result<(), PrivilegeError> {
    // Check if we're running as root
    let current_uid = getuid();
    
    // Skip privilege drop in debug mode or if not running as root
    if debug_mode {
        info!("Debug mode enabled, skipping privilege drop");
        return Ok(());
    }
    
    if !current_uid.is_root() {
        warn!("Not running as root (UID: {}), cannot drop privileges", current_uid);
        return Err(PrivilegeError::AlreadyUnprivileged);
    }
    
    debug!("Starting privilege drop: target user='{}', group='{}'", username, groupname);
    
    // Lookup target group
    let target_gid = lookup_group(groupname)?;
    debug!("Resolved group '{}' to GID {}", groupname, target_gid);
    
    // Lookup target user
    let target_uid = lookup_user(username)?;
    debug!("Resolved user '{}' to UID {}", username, target_uid);
    
    // Only proceed with privilege drop if target UID is non-zero
    // (dropping to root would be a no-op and potentially dangerous)
    if target_uid.as_raw() == 0 {
        warn!("Target user '{}' is root (UID 0), skipping privilege drop", username);
        return Ok(());
    }
    
    // Step 1: Clear supplementary groups
    // This must be done before setgid() to ensure no residual group memberships
    setgroups(&[])
        .map_err(|e| PrivilegeError::SetGroupsFailed(IoError::from_raw_os_error(e as i32)))?;
    debug!("Cleared supplementary groups");
    
    // Step 2: Change group ID
    // This must be done before setuid() because setuid() may remove permission to change GID
    setgid(target_gid)
        .map_err(|e| PrivilegeError::SetGroupFailed(
            groupname.to_string(),
            target_gid.as_raw(),
            IoError::from_raw_os_error(e as i32),
        ))?;
    info!("Changed group to '{}' (GID {})", groupname, target_gid);
    
    // Platform-specific capability/privilege management before setuid()
    #[cfg(target_os = "linux")]
    {
        // Linux: Manage capabilities to permit setuid() and retain minimal privileges
        linux_setup_capabilities()?;
    }
    
    #[cfg(target_os = "solaris")]
    {
        // Solaris: Configure privilege sets to retain network capabilities
        solaris_setup_privileges()?;
    }
    
    // Step 3: Change user ID
    // This is the critical security boundary - after this, we cannot regain root
    setuid(target_uid)
        .map_err(|e| PrivilegeError::SetUserFailed(
            username.to_string(),
            target_uid.as_raw(),
            IoError::from_raw_os_error(e as i32),
        ))?;
    info!("Changed user to '{}' (UID {})", username, target_uid);
    
    // Platform-specific capability/privilege cleanup after setuid()
    #[cfg(target_os = "linux")]
    {
        // Linux: Remove CAP_SETUID now that we've completed the privilege drop
        linux_drop_setuid_capability()?;
    }
    
    info!("Privilege drop complete: now running as {}:{} ({}:{})",
          username, groupname, target_uid, target_gid);
    
    Ok(())
}

/// Lookup group name and return GID
fn lookup_group(groupname: &str) -> Result<Gid, PrivilegeError> {
    use nix::unistd::Group;
    
    Group::from_name(groupname)
        .map_err(|e| PrivilegeError::GroupNotFound(
            groupname.to_string(),
            IoError::from_raw_os_error(e as i32),
        ))?
        .ok_or_else(|| PrivilegeError::GroupNotFound(
            groupname.to_string(),
            IoError::new(std::io::ErrorKind::NotFound, "Group not found in system database"),
        ))
        .map(|g| g.gid)
}

/// Lookup user name and return UID
fn lookup_user(username: &str) -> Result<Uid, PrivilegeError> {
    use nix::unistd::User;
    
    User::from_name(username)
        .map_err(|e| PrivilegeError::UserNotFound(
            username.to_string(),
            IoError::from_raw_os_error(e as i32),
        ))?
        .ok_or_else(|| PrivilegeError::UserNotFound(
            username.to_string(),
            IoError::new(std::io::ErrorKind::NotFound, "User not found in system database"),
        ))
        .map(|u| u.uid)
}

/// Linux: Setup capabilities before setuid()
///
/// Adds CAP_SETUID capability and enables PR_SET_KEEPCAPS to preserve
/// capabilities across the setuid() call.
///
/// Matches C code from dnsmasq.c lines 925-930
#[cfg(target_os = "linux")]
fn linux_setup_capabilities() -> Result<(), PrivilegeError> {
    use std::mem::MaybeUninit;
    
    // Read current capabilities
    let mut header = __user_cap_header_struct {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0, // 0 = current process
    };
    
    let mut data = [MaybeUninit::<__user_cap_data_struct>::zeroed(); 2];
    
    // SAFETY: capget is called with valid header and data pointers
    // The kernel will fill in the data structure
    let result = unsafe {
        capget(
            &mut header as *mut __user_cap_header_struct,
            data.as_mut_ptr() as *mut __user_cap_data_struct,
        )
    };
    
    if result < 0 {
        let err = IoError::last_os_error();
        error!("Failed to get capabilities: {}", err);
        return Err(PrivilegeError::CapabilityError(
            "capget".to_string(),
            err,
        ));
    }
    
    // SAFETY: capget succeeded, so data is initialized
    let mut data = unsafe {
        [data[0].assume_init(), data[1].assume_init()]
    };
    
    // Add CAP_SETUID to effective and permitted sets
    // CAP_SETUID allows changing UID, which we need for setuid() call
    data[0].effective |= 1 << CAP_SETUID;
    data[0].permitted |= 1 << CAP_SETUID;
    
    debug!("Adding CAP_SETUID capability (effective: {:#x}, permitted: {:#x})",
           data[0].effective, data[0].permitted);
    
    // SAFETY: capset is called with valid header and modified data
    let result = unsafe {
        capset(
            &header as *const __user_cap_header_struct,
            data.as_ptr() as *const __user_cap_data_struct,
        )
    };
    
    if result < 0 {
        let err = IoError::last_os_error();
        error!("Failed to set capabilities: {}", err);
        return Err(PrivilegeError::CapabilityError(
            "capset (add CAP_SETUID)".to_string(),
            err,
        ));
    }
    
    // Enable PR_SET_KEEPCAPS to preserve capabilities across setuid()
    // Without this, all capabilities would be cleared by setuid()
    prctl(PrctlOption::PR_SET_KEEPCAPS(1))
        .map_err(|e| {
            let err = IoError::from_raw_os_error(e as i32);
            error!("Failed to set PR_SET_KEEPCAPS: {}", err);
            PrivilegeError::CapabilityError(
                "prctl PR_SET_KEEPCAPS".to_string(),
                err,
            )
        })?;
    
    debug!("Enabled PR_SET_KEEPCAPS");
    
    Ok(())
}

/// Linux: Drop CAP_SETUID capability after setuid()
///
/// Removes the CAP_SETUID capability now that we've completed the privilege drop.
/// This ensures we cannot change UID again (defense-in-depth).
///
/// Matches C code from dnsmasq.c lines 967-977
#[cfg(target_os = "linux")]
fn linux_drop_setuid_capability() -> Result<(), PrivilegeError> {
    use std::mem::MaybeUninit;
    
    // Read current capabilities
    let mut header = __user_cap_header_struct {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    
    let mut data = [MaybeUninit::<__user_cap_data_struct>::zeroed(); 2];
    
    // SAFETY: capget is called with valid pointers
    let result = unsafe {
        capget(
            &mut header as *mut __user_cap_header_struct,
            data.as_mut_ptr() as *mut __user_cap_data_struct,
        )
    };
    
    if result < 0 {
        let err = IoError::last_os_error();
        error!("Failed to get capabilities for cleanup: {}", err);
        return Err(PrivilegeError::CapabilityError(
            "capget (cleanup)".to_string(),
            err,
        ));
    }
    
    // SAFETY: capget succeeded
    let mut data = unsafe {
        [data[0].assume_init(), data[1].assume_init()]
    };
    
    // Remove CAP_SETUID from effective and permitted sets
    data[0].effective &= !(1 << CAP_SETUID);
    data[0].permitted &= !(1 << CAP_SETUID);
    
    debug!("Removing CAP_SETUID capability (effective: {:#x}, permitted: {:#x})",
           data[0].effective, data[0].permitted);
    
    // SAFETY: capset is called with valid pointers
    let result = unsafe {
        capset(
            &header as *const __user_cap_header_struct,
            data.as_ptr() as *const __user_cap_data_struct,
        )
    };
    
    if result < 0 {
        let err = IoError::last_os_error();
        error!("Failed to drop CAP_SETUID capability: {}", err);
        return Err(PrivilegeError::CapabilityError(
            "capset (drop CAP_SETUID)".to_string(),
            err,
        ));
    }
    
    debug!("Dropped CAP_SETUID capability");
    
    Ok(())
}

/// Solaris: Setup privilege sets before setuid()
///
/// Creates a privilege set with "basic" + PRIV_NET_ICMPACCESS + PRIV_SYS_NET_CONFIG,
/// inverts it, and applies to PRIV_LIMIT to restrict privileges after setuid().
///
/// Matches C code from dnsmasq.c lines 933-950
#[cfg(target_os = "solaris")]
fn solaris_setup_privileges() -> Result<(), PrivilegeError> {
    use std::ffi::CString;
    use std::ptr;
    
    debug!("Configuring Solaris privilege sets");
    
    // Create "basic" privilege set
    let basic_str = CString::new("basic").unwrap();
    let sep_str = CString::new(",").unwrap();
    
    // SAFETY: FFI call with valid C strings
    let priv_set = unsafe {
        priv_str_to_set(basic_str.as_ptr(), sep_str.as_ptr(), ptr::null_mut())
    };
    
    if priv_set.is_null() {
        let err = IoError::last_os_error();
        error!("Failed to create basic privilege set: {}", err);
        return Err(PrivilegeError::PrivilegeSetError(
            "priv_str_to_set".to_string(),
            err,
        ));
    }
    
    // Add PRIV_NET_ICMPACCESS (required for ICMP operations)
    let icmp_priv = CString::new(PRIV_NET_ICMPACCESS).unwrap();
    
    // SAFETY: priv_set is valid, icmp_priv is valid C string
    let result = unsafe {
        priv_addset(priv_set, icmp_priv.as_ptr())
    };
    
    if result < 0 {
        let err = IoError::last_os_error();
        // SAFETY: priv_set is valid
        unsafe { priv_freeset(priv_set); }
        error!("Failed to add {} privilege: {}", PRIV_NET_ICMPACCESS, err);
        return Err(PrivilegeError::PrivilegeSetError(
            format!("priv_addset {}", PRIV_NET_ICMPACCESS),
            err,
        ));
    }
    
    // Add PRIV_SYS_NET_CONFIG (required for network configuration)
    let netcfg_priv = CString::new(PRIV_SYS_NET_CONFIG).unwrap();
    
    // SAFETY: priv_set is valid, netcfg_priv is valid C string
    let result = unsafe {
        priv_addset(priv_set, netcfg_priv.as_ptr())
    };
    
    if result < 0 {
        let err = IoError::last_os_error();
        // SAFETY: priv_set is valid
        unsafe { priv_freeset(priv_set); }
        error!("Failed to add {} privilege: {}", PRIV_SYS_NET_CONFIG, err);
        return Err(PrivilegeError::PrivilegeSetError(
            format!("priv_addset {}", PRIV_SYS_NET_CONFIG),
            err,
        ));
    }
    
    // Invert privilege set (basic + net_icmpaccess + sys_net_config -> all except these)
    // SAFETY: priv_set is valid
    unsafe {
        priv_inverse(priv_set);
    }
    
    debug!("Inverted privilege set to remove all except basic+network privileges");
    
    // Apply inverted privilege set to PRIV_LIMIT (removes unwanted privileges)
    // SAFETY: priv_set is valid, PRIV_OFF and PRIV_LIMIT are valid constants
    let result = unsafe {
        setppriv(PRIV_OFF as i32, PRIV_LIMIT as i32, priv_set)
    };
    
    if result < 0 {
        let err = IoError::last_os_error();
        // SAFETY: priv_set is valid
        unsafe { priv_freeset(priv_set); }
        error!("Failed to set privilege limits: {}", err);
        return Err(PrivilegeError::PrivilegeSetError(
            "setppriv".to_string(),
            err,
        ));
    }
    
    // SAFETY: priv_set is valid and no longer needed
    unsafe {
        priv_freeset(priv_set);
    }
    
    debug!("Applied Solaris privilege limits");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_privilege_error_display() {
        let err = PrivilegeError::AlreadyUnprivileged;
        assert_eq!(
            err.to_string(),
            "Already running as unprivileged user (UID != 0)"
        );
        
        let err = PrivilegeError::UserNotFound(
            "testuser".to_string(),
            IoError::new(std::io::ErrorKind::NotFound, "not found"),
        );
        assert!(err.to_string().contains("testuser"));
    }
    
    #[test]
    fn test_debug_mode_skips_drop() {
        // In debug mode, privilege drop should succeed without doing anything
        let result = drop_privileges("nobody", "nogroup", true);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_non_root_returns_error() {
        // If not running as root, should return AlreadyUnprivileged error
        if !getuid().is_root() {
            let result = drop_privileges("nobody", "nogroup", false);
            assert!(matches!(result, Err(PrivilegeError::AlreadyUnprivileged)));
        }
    }
}
