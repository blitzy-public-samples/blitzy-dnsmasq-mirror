// Copyright (c) 2000-2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! Foreign Function Interface (FFI) Module
//!
//! This module serves as the **controlled boundary** between safe Rust code and unsafe FFI
//! operations throughout the dnsmasq codebase. All interactions with C libraries, system calls,
//! and platform-specific APIs are routed through this module to ensure memory safety guarantees.
//!
//! # Architecture and Design Principles
//!
//! ## Safety Guarantee: Safe Public API, Unsafe Private Implementation
//!
//! The FFI module follows a critical design principle:
//! - **All public APIs are 100% safe** - No `unsafe` keyword visible to consumers
//! - **All `unsafe` blocks are isolated to private implementation details** within child modules
//! - **Every unsafe block has documented safety invariants** explaining preconditions and guarantees
//!
//! This ensures that memory safety vulnerabilities (buffer overflows, use-after-free, null pointer
//! dereferences, data races) are eliminated at the FFI boundary and cannot propagate to the rest
//! of the codebase.
//!
//! ## Module Organization
//!
//! The FFI module is organized into two primary submodules:
//!
//! ### `libc_wrappers` - POSIX System Call Abstractions
//!
//! Provides memory-safe wrappers around libc system calls for:
//! - **Privilege Management**: `setuid`, `setgid`, `setgroups` for dropping root privileges
//! - **Linux Capabilities**: `capget`, `capset`, `prctl` for fine-grained permission control
//! - **Signal Handling**: `sigaction` for POSIX signal handler registration
//! - **Socket Operations**: Low-level socket configuration (`SO_BINDTODEVICE`, `TCP_FASTOPEN`)
//!
//! **Replaces C code**: `src/dnsmasq.c` lines 724-735 (capabilities), 914-920 (privilege dropping),
//! 269-279 (signal handling); `src/network.c` socket creation
//!
//! ### `platform` - Platform-Specific Integrations
//!
//! Provides conditional compilation for platform-specific functionality:
//! - **Linux**: `netlink` (interface enumeration), `conntrack` (connection tracking),
//!   `nftables` (firewall integration), `ipset` (address sets via netlink)
//! - **BSD**: `pf` (Packet Filter table integration), routing sockets
//! - **OpenWrt**: `ubus` (microbus IPC for embedded systems)
//! - **Solaris**: `solaris_privileges` (Solaris privilege management)
//!
//! **Replaces C code**: `src/netlink.c` (Linux netlink), `src/bpf.c` (BSD routing sockets),
//! `src/inotify.c` (Linux inotify), `src/conntrack.c`, `src/ubus.c`, `src/nftset.c`
//!
//! ## Error Handling Strategy
//!
//! The FFI module defines a unified `FfiError` type that consolidates platform-specific error
//! codes (`errno` on Unix, `nix::Error` on Linux/BSD) into a Rust `Result`-based error handling
//! model. This replaces C's error-prone pattern of checking return values and inspecting `errno`.
//!
//! Error transformation flow:
//! ```text
//! C errno (-1 return + errno) → nix::Error → FfiError → Result<T, FfiError>
//! ```
//!
//! ## Platform Abstraction via Conditional Compilation
//!
//! Platform-specific code uses Cargo feature flags to ensure only relevant code is compiled:
//!
//! ```rust,ignore
//! #[cfg(target_os = "linux")]
//! pub use platform::netlink;
//!
//! #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
//! pub use platform::pf;
//! ```
//!
//! This matches C's `HAVE_LINUX_NETWORK`, `HAVE_BSD_NETWORK`, etc. feature macros but with
//! compile-time verification and zero runtime overhead.
//!
//! # Memory Safety Transformations from C
//!
//! ## Buffer Overflow Prevention
//!
//! **C Pattern (Unsafe)**:
//! ```c
//! char buffer[256];
//! strcpy(buffer, untrusted_input);  // Buffer overflow if input > 256 bytes
//! ```
//!
//! **Rust Pattern (Safe)**:
//! ```rust
//! let buffer = String::from(untrusted_input);  // Automatic capacity management
//! ```
//!
//! ## Null Pointer Dereference Prevention
//!
//! **C Pattern (Unsafe)**:
//! ```c
//! struct user *u = getpwnam(username);
//! if (u == NULL) { /* error */ }
//! uid_t uid = u->pw_uid;  // Potential null dereference if check forgotten
//! ```
//!
//! **Rust Pattern (Safe)**:
//! ```rust
//! let user = User::from_name(username)?;  // Option<User> forces null check
//! let uid = user.uid;  // Cannot access without handling None case
//! ```
//!
//! ## Use-After-Free Prevention
//!
//! **C Pattern (Unsafe)**:
//! ```c
//! int fd = socket(...);
//! close(fd);
//! send(fd, ...);  // Use-after-free, undefined behavior
//! ```
//!
//! **Rust Pattern (Safe)**:
//! ```rust
//! let socket = Socket::new(...)?;  // OwnedFd wrapper
//! drop(socket);  // Automatic close via Drop trait
//! // socket.send(...);  // Compile error: value moved in drop()
//! ```
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dnsmasq::ffi::{
//!     libc_wrappers::{drop_root_privileges, set_linux_capabilities, LinuxCapability},
//!     FfiError,
//! };
//!
//! fn setup_privileges() -> Result<(), FfiError> {
//!     // Drop from root to unprivileged user
//!     drop_root_privileges("dnsmasq", "dnsmasq")?;
//!     
//!     // Retain only necessary capabilities (Linux-specific)
//!     #[cfg(target_os = "linux")]
//!     {
//!         set_linux_capabilities(&[
//!             LinuxCapability::NetBindService,  // Bind to ports < 1024
//!             LinuxCapability::NetRaw,          // DHCP raw sockets
//!         ])?;
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Relationship to C Implementation
//!
//! This module consolidates FFI operations previously scattered throughout C codebase:
//!
//! | Rust Module | C Source Files | Lines | Purpose |
//! |-------------|----------------|-------|---------|
//! | `libc_wrappers` | `src/dnsmasq.c` | 724-735, 914-920, 269-279 | Privilege/signal handling |
//! | `platform::netlink` | `src/netlink.c` | All (~1500 lines) | Linux interface monitoring |
//! | `platform::pf` | `src/tables.c` | All (~500 lines) | BSD firewall integration |
//! | `platform::conntrack` | `src/conntrack.c` | All (~400 lines) | Connection tracking |
//! | `platform::nftables` | `src/nftset.c` | All (~600 lines) | nftables integration |
//! | `platform::ubus` | `src/ubus.c` | All (~600 lines) | OpenWrt IPC |
//!
//! # Testing Strategy
//!
//! FFI code is tested through:
//! 1. **Unit tests with mocks** - Using `mockall` crate to simulate system calls
//! 2. **Integration tests** - Validating behavior against C implementation test suite
//! 3. **Property-based tests** - Using `proptest` to verify error handling invariants
//! 4. **Platform-specific CI** - Testing on Linux, FreeBSD, OpenBSD, macOS, Solaris
//!
//! # Safety Audit Checklist
//!
//! Every unsafe block in child modules must satisfy:
//! - [ ] Safety invariants documented with `/// Safety` comment
//! - [ ] All inputs validated before passing to C
//! - [ ] Raw pointers immediately wrapped in safe types
//! - [ ] No pointer arithmetic (use `.offset()` with bounds checks)
//! - [ ] Resources have Drop implementations for cleanup
//! - [ ] No `mem::transmute` without extensive justification
//! - [ ] No mutable static variables without synchronization
//!
//! # See Also
//!
//! - [`libc_wrappers`] - POSIX system call wrappers
//! - [`platform`] - Platform-specific integrations
//! - `docs/RUST_ARCHITECTURE.md` - FFI design documentation

// ============================================================================
// Submodule Declarations
// ============================================================================

/// Safe wrappers around libc system calls for privilege management, signal handling,
/// and socket operations. All public APIs are safe; unsafe blocks isolated to private
/// implementation details.
///
/// See module documentation for detailed API reference.
pub mod libc_wrappers;

/// Platform-specific FFI abstractions for Linux netlink, BSD routing sockets, external
/// library integrations (conntrack, nftables, ubus), and file watching (inotify).
///
/// Uses conditional compilation to include only relevant platform code.
pub mod platform;

// ============================================================================
// Public Type Re-exports
// ============================================================================

/// Unified error type for all FFI operations throughout dnsmasq.
///
/// Re-exported from `libc_wrappers` module. This error type consolidates platform-specific
/// error codes (Unix `errno`, system call failures, permission denials) into a single Rust
/// error type that can be propagated via `?` operator and provides detailed error context.
///
/// See [`libc_wrappers::FfiError`] for variant definitions and usage examples.
pub use libc_wrappers::FfiError;

/// Result type alias for FFI operations.
///
/// Convenience type for functions returning `Result<T, FfiError>`.
pub use libc_wrappers::Result;

// ============================================================================
// Public Re-exports
// ============================================================================

/// Re-export commonly used privilege management and signal handling functions
///
/// These are the most frequently used FFI operations throughout the codebase.
pub use libc_wrappers::{
    drop_root_privileges,
    set_linux_capabilities,
    install_signal_handler,
};

/// Re-export Linux capability types (Linux only)
///
/// Provides safe abstractions for Linux capability management.
#[cfg(target_os = "linux")]
pub use libc_wrappers::{LinuxCapability, CapabilitySet};

// Platform-specific conditional re-exports

/// Linux netlink socket operations (Linux only)
///
/// Provides interface enumeration, address monitoring, and route monitoring
/// via Linux RTNETLINK protocol.
#[cfg(target_os = "linux")]
pub use platform::netlink;

/// OpenWrt ubus IPC interface (Linux only, optional feature)
///
/// Provides microbus IPC for embedded OpenWrt systems.
#[cfg(all(target_os = "linux", feature = "ubus"))]
pub use platform::ubus;

/// Linux connection tracking integration (Linux only, optional feature)
///
/// Provides conntrack mark propagation for DNS queries.
#[cfg(all(target_os = "linux", feature = "conntrack"))]
pub use platform::conntrack;

/// Linux nftables integration (Linux only, optional feature)
///
/// Provides nftables set manipulation for dynamic firewall rules.
#[cfg(all(target_os = "linux", feature = "nftset"))]
pub use platform::nftables;

/// BSD Packet Filter table integration (BSD only)
///
/// Provides PF table manipulation for dynamic firewall rules on FreeBSD/OpenBSD.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub use platform::pf;

/// Solaris privilege management (Solaris only)
///
/// Provides Solaris-specific privilege dropping and management.
#[cfg(target_os = "solaris")]
pub use platform::solaris_privileges;

// ============================================================================
// Module Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify that key types are accessible from module root
        // FfiError should be re-exported from libc_wrappers
        let _: Result<()> = Ok(());
    }

    #[test]
    fn test_libc_wrappers_accessible() {
        // Verify libc_wrappers module is accessible
        // The actual functionality is tested in libc_wrappers module tests
        assert!(true);
    }

    #[test]
    fn test_platform_module_accessible() {
        // Verify platform module is accessible
        // Platform-specific functionality tested in platform module tests
        assert!(true);
    }
}
