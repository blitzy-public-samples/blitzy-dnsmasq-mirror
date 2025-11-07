// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later

//! Generic POSIX platform implementations
//!
//! This module provides fallback network interface operations for platforms without
//! specialized native monitoring APIs. It uses standard POSIX interfaces available
//! on all Unix-like systems that comply with RFC 3493 and POSIX.1-2001 standards.
//!
//! # Platform Selection
//!
//! This module is automatically selected via conditional compilation when the target
//! operating system is **NOT** one of the following:
//! - Linux (which uses netlink via `src/platform/linux/netlink.rs`)
//! - FreeBSD, OpenBSD, NetBSD, DragonFly BSD (which use BPF via `src/platform/bsd/bpf.rs`)
//! - macOS (which uses macOS-specific APIs via `src/platform/macos/`)
//!
//! Supported fallback platforms include:
//! - Solaris (with `getifaddrs()` support in newer versions)
//! - AIX, HP-UX, and other commercial Unix variants
//! - Any POSIX-compliant system providing `getifaddrs()`, `if_nametoindex()`, and `if_indextoname()`
//!
//! # C Implementation Context
//!
//! This module replaces the `#else` fallback clauses in `src/network.c` (lines 251-299)
//! which provided BSD-style interface enumeration for platforms without Linux netlink
//! or BSD-specific routing socket APIs. The C implementation's comment states:
//!
//! > "BSD and generic Unix implementation using POSIX standard if_indextoname() function."
//!
//! The original C code used:
//! - `getifaddrs()` for interface enumeration (BSD-originated, now POSIX.1-2008)
//! - `if_indextoname()` / `if_nametoindex()` for index/name conversion (RFC 3493)
//! - Manual linked list traversal with `freeifaddrs()` cleanup
//! - SIOCGIFCONF ioctl fallback for ancient Unix systems (removed in Rust version)
//!
//! # Architecture and Design
//!
//! ## Polling-Based Change Detection
//!
//! Unlike Linux (netlink `RTMGRP_LINK` multicast) and BSD (routing socket `RTM_IFINFO`
//! messages) which provide event-driven interface change notifications, this generic
//! implementation uses **polling-based change detection**:
//!
//! 1. **Initial Enumeration**: Call `enumerate_interfaces()` to get baseline state
//! 2. **Periodic Re-enumeration**: Every 30 seconds (configurable), call `enumerate_interfaces()` again
//! 3. **State Comparison**: Compare new interface list with cached baseline
//! 4. **Change Detection**: If differences found (count, names, indices, addresses), report change
//! 5. **Cache Update**: Update cached state with new interface list
//!
//! ### Trade-offs
//!
//! **Latency**: Interface changes are detected with latency up to the polling interval
//! (default 30 seconds). Event-driven platforms detect changes within milliseconds.
//!
//! **Overhead**: Periodic `getifaddrs()` syscalls consume CPU cycles and generate
//! kernel context switches. Event-driven platforms only process actual events.
//!
//! **Portability**: Works on any POSIX-compliant system without requiring platform-specific
//! kernel APIs, ensuring dnsmasq-rs can run on obscure or legacy Unix variants.
//!
//! ## Memory Safety Benefits
//!
//! The C implementation manually manages `getifaddrs()` linked lists:
//!
//! ```c
//! struct ifaddrs *ifa, *ifp;
//! if (getifaddrs(&ifa) == 0) {
//!     for (ifp = ifa; ifp; ifp = ifp->ifa_next) {
//!         // Process interface...
//!     }
//!     freeifaddrs(ifa);  // Manual cleanup - risk of memory leaks if forgotten
//! }
//! ```
//!
//! Rust's `nix` crate provides RAII-based wrappers that automatically free memory
//! via the `Drop` trait, eliminating:
//! - **Memory leaks** from forgotten `freeifaddrs()` calls
//! - **Use-after-free** from accessing `ifa` after `freeifaddrs()`
//! - **Double-free** from calling `freeifaddrs()` multiple times
//!
//! ## Module Organization
//!
//! This `mod.rs` serves as the module root for the generic platform implementation:
//!
//! - **`network.rs`**: Core implementation of `GenericPlatform` struct with POSIX
//!   interface enumeration, index/name conversion, and polling-based monitoring.
//!
//! ### Public API Re-exports
//!
//! The following items are re-exported at the module level for convenient access:
//!
//! - **`GenericPlatform`**: Main platform implementation struct providing the
//!   `NetworkPlatform` trait interface from `src/platform/mod.rs`.
//!
//! # Usage Example
//!
//! ```ignore
//! use crate::platform::generic::GenericPlatform;
//! use crate::platform::NetworkPlatform;
//!
//! // Create generic platform instance (automatically selected on Solaris, AIX, etc.)
//! let platform = GenericPlatform::new();
//!
//! // Enumerate all network interfaces using POSIX getifaddrs()
//! let interfaces = platform.enumerate_interfaces()?;
//! for iface in interfaces {
//!     println!("Interface {}: index={}, addresses={:?}",
//!              iface.name, iface.index, iface.addresses);
//! }
//!
//! // Convert interface index to name using POSIX if_indextoname()
//! if let Some(name) = platform.index_to_name(3) {
//!     println!("Interface index 3 is {}", name);
//! }
//!
//! // Check for interface changes (polling-based)
//! if platform.check_interface_changes()? {
//!     println!("Network topology changed, reloading listeners");
//! }
//! ```
//!
//! # Limitations
//!
//! This generic implementation has several limitations compared to platform-specific
//! implementations:
//!
//! ## 1. No Advanced Socket Options
//!
//! - **SO_BINDTODEVICE** (Linux): Not available. Sockets cannot be bound exclusively
//!   to a specific interface by name. Must bind to specific addresses instead.
//!
//! - **IP_BOUND_IF** (BSD): Not available. Similar limitation to SO_BINDTODEVICE.
//!
//! - **SO_REUSEPORT** (Linux/BSD): May not be available on all POSIX systems.
//!   Generic implementation only uses SO_REUSEADDR.
//!
//! ## 2. No Real-Time Change Notifications
//!
//! Interface changes (address add/remove, link up/down, interface hotplug) are only
//! detected during periodic re-enumeration. Applications requiring immediate response
//! to network topology changes should use Linux or BSD platforms.
//!
//! ## 3. Limited Interface Metadata
//!
//! Some interface properties available on Linux (via netlink) or BSD (via routing
//! sockets) are not accessible through POSIX `getifaddrs()`:
//! - Interface MTU (Maximum Transmission Unit)
//! - Link layer statistics (packets sent/received, errors, drops)
//! - Hardware address (MAC address) - may not be available on all platforms
//! - Interface alias names
//!
//! ## 4. Performance Overhead
//!
//! Periodic re-enumeration of all interfaces generates syscall overhead. On systems
//! with many interfaces (100+), this can become noticeable. Event-driven platforms
//! only process actual change events.
//!
//! # Conditional Compilation
//!
//! This module is enabled via Cargo feature flags and `cfg` attributes. The parent
//! `src/platform/mod.rs` uses conditional compilation to select the appropriate
//! platform implementation:
//!
//! ```ignore
//! #[cfg(not(any(
//!     target_os = "linux",
//!     target_os = "freebsd",
//!     target_os = "openbsd",
//!     target_os = "netbsd",
//!     target_os = "dragonfly",
//!     target_os = "macos"
//! )))]
//! pub mod generic;
//! ```
//!
//! # Integration with Parent Module
//!
//! The `GenericPlatform` struct implements the `NetworkPlatform` trait defined in
//! `src/platform/mod.rs`, providing a uniform interface for network operations
//! across all supported platforms. This allows the main dnsmasq-rs daemon to use
//! platform abstraction without conditional compilation in core logic:
//!
//! ```ignore
//! // In src/main.rs or src/runtime/daemon.rs
//! let platform = platform::create_platform(); // Returns Box<dyn NetworkPlatform>
//! let interfaces = platform.enumerate_interfaces()?;
//! ```
//!
//! # POSIX Standards Compliance
//!
//! This implementation relies on the following POSIX and RFC standards:
//!
//! - **POSIX.1-2008**: `getifaddrs()` function for interface enumeration
//! - **RFC 3493**: `if_nametoindex()` and `if_indextoname()` for index/name conversion
//! - **POSIX.1-2001**: Socket API (`socket()`, `bind()`, `setsockopt()`)
//! - **RFC 2553**: IPv6 socket address structures (`sockaddr_in6`)
//!
//! # See Also
//!
//! - [`src/platform/mod.rs`](../mod.rs) - Platform abstraction trait definitions
//! - [`src/platform/linux/netlink.rs`](../linux/netlink.rs) - Linux netlink implementation
//! - [`src/platform/bsd/bpf.rs`](../bsd/bpf.rs) - BSD BPF and routing socket implementation
//! - [`src/network/`](../../network/) - High-level networking abstractions
//! - [RFC 3493](https://tools.ietf.org/html/rfc3493) - Basic Socket Interface Extensions for IPv6
//! - [POSIX.1-2008 getifaddrs()](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getifaddrs.html)

// Generic POSIX networking fallback
pub mod network;

// Re-export GenericPlatform for convenient access
//
// This allows users to write:
//   use crate::platform::generic::GenericPlatform;
//
// Instead of:
//   use crate::platform::generic::network::GenericPlatform;
//
// The GenericPlatform struct provides all required NetworkPlatform trait methods:
// - new() - Create new instance with default polling interval
// - enumerate_interfaces() - Get all network interfaces using getifaddrs()
// - init_monitoring() - Initialize polling-based change detection
// - get_interface_by_index() - Look up interface by index
// - index_to_name() - Convert interface index to name using if_indextoname()
// - name_to_index() - Convert interface name to index using if_nametoindex()
// - check_interface_changes() - Detect changes via periodic re-enumeration
pub use network::GenericPlatform;
