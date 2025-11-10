// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; version 2 dated June, 1991, or
//  (at your option) version 3 dated 29 June, 2007.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//    
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Build script for dnsmasq Rust implementation
//!
//! This script replicates the feature detection logic from the C Makefile
//! (lines 54-74) and bld/pkg-wrapper script. It detects optional system
//! libraries and configures Cargo features accordingly.
//!
//! ## Feature Detection
//!
//! The following optional dependencies are detected via pkg-config:
//! - dbus-1: D-Bus IPC support → enables 'dbus' feature
//! - libidn2: Internationalized Domain Names → enables 'idn' feature
//! - nettle + hogweed: Cryptography for DNSSEC → enables 'dnssec' feature
//! - libnftables (≥0.9): nftables integration
//! - `libnetfilter_conntrack`: Connection tracking
//! - lua5.2: Lua scripting support → enables 'lua' feature
//! - libubus + libubox: `OpenWrt` ubus integration (Linux only)
//!
//! ## Platform Detection
//!
//! Platform-specific code paths are configured via rustc-cfg:
//! - Linux: netlink sockets, inotify, conntrack, ipset, nftables
//! - BSD (FreeBSD, OpenBSD, NetBSD): routing sockets, BPF, PF tables
//! - macOS: BSD-style networking with platform-specific quirks
//! - Solaris: ioctl-based interface enumeration
//!
//! ## Version Stamping
//!
//! The build script reads VERSION file or runs `git describe` to embed
//! version information into the binary, matching C Makefile line 75.

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    // Rebuild if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");
    
    // Rebuild if VERSION file changes
    if Path::new("VERSION").exists() {
        println!("cargo:rerun-if-changed=VERSION");
    }
    
    // Detect and configure platform-specific features
    detect_platform();
    
    // Detect optional system libraries and enable features
    detect_optional_libraries();
    
    // Stamp version information
    stamp_version();
    
    println!("cargo:warning=Build configuration complete");
}

/// Detects the target platform and emits appropriate rustc-cfg directives.
///
/// This replicates platform detection from the C codebase which uses
/// conditional compilation via `HAVE_LINUX_NETWORK`, `HAVE_BSD_NETWORK`, etc.
///
/// Emits:
/// - `cargo:rustc-cfg=platform_linux` for Linux
/// - `cargo:rustc-cfg=platform_bsd` for BSD variants
/// - `cargo:rustc-cfg=platform_macos` for macOS
/// - `cargo:rustc-cfg=platform_solaris` for Solaris
fn detect_platform() {
    let target_os = env::var("CARGO_CFG_TARGET_OS")
        .expect("CARGO_CFG_TARGET_OS not set");
    
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-cfg=platform_linux");
            println!("cargo:warning=Configuring for Linux (netlink, inotify support)");
        }
        "freebsd" | "openbsd" | "netbsd" | "dragonfly" => {
            println!("cargo:rustc-cfg=platform_bsd");
            println!("cargo:warning=Configuring for BSD (routing sockets, BPF support)");
        }
        "macos" => {
            println!("cargo:rustc-cfg=platform_macos");
            println!("cargo:warning=Configuring for macOS");
        }
        "solaris" | "illumos" => {
            println!("cargo:rustc-cfg=platform_solaris");
            println!("cargo:warning=Configuring for Solaris/illumos");
        }
        other => {
            println!("cargo:warning=Unsupported platform: {}. Build may fail.", other);
        }
    }
}

/// Detects optional system libraries using pkg-config.
///
/// This replicates the logic from Makefile lines 54-74 and bld/pkg-wrapper.
/// Each detected library causes:
/// 1. Feature flag emission via `cargo:rustc-cfg=feature=\"name\"`
/// 2. Library linking via `cargo:rustc-link-lib=dylib=name`
/// 3. Include path setup via `cargo:rustc-link-search=native=path`
///
/// Libraries are optional - missing libraries result in warnings but do not
/// fail the build (graceful degradation).
fn detect_optional_libraries() {
    // D-Bus support (uk.org.thekelleys.dnsmasq control interface)
    detect_library(
        "dbus-1",
        "dbus",
        "D-Bus IPC support for control interface",
        None,
    );
    
    // IDN (Internationalized Domain Names) support
    detect_library(
        "libidn2",
        "idn",
        "Internationalized Domain Name support",
        None,
    );
    
    // DNSSEC cryptography (nettle + hogweed for RSA, ECDSA, Ed25519)
    detect_dnssec_libraries();
    
    // Linux conntrack integration
    detect_library(
        "libnetfilter_conntrack",
        "conntrack",
        "Linux connection tracking integration",
        None,
    );
    
    // nftables integration (requires ≥0.9)
    detect_library(
        "libnftables",
        "nftables",
        "nftables integration for packet filtering",
        Some("0.9.0"),
    );
    
    // Lua scripting support
    detect_library(
        "lua5.2",
        "lua",
        "Lua 5.2 scripting support for dynamic hooks",
        None,
    );
    
    // OpenWrt ubus integration (Linux only)
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "linux" {
        detect_ubus_libraries();
    }
}

/// Detects a single library via pkg-config and configures linking.
///
/// # Arguments
/// * `pkg_name` - Package name for pkg-config (e.g., "dbus-1")
/// * `feature_name` - Cargo feature name to enable (e.g., "dbus")
/// * `description` - Human-readable description for log messages
/// * `min_version` - Optional minimum version requirement
fn detect_library(
    pkg_name: &str,
    feature_name: &str,
    description: &str,
    min_version: Option<&str>,
) {
    let probe_result = if let Some(version) = min_version {
        pkg_config::Config::new()
            .atleast_version(version)
            .probe(pkg_name)
    } else {
        pkg_config::probe_library(pkg_name)
    };
    
    match probe_result {
        Ok(library) => {
            // Enable Cargo feature
            println!("cargo:rustc-cfg=feature=\"{}\"", feature_name);
            
            // Link the library (pkg-config handles this automatically via rustc-link-lib)
            // The library crate already emits the necessary link directives
            
            println!(
                "cargo:warning=✓ {} detected (version {})",
                description,
                library.version
            );
        }
        Err(e) => {
            println!(
                "cargo:warning=✗ {} not found: {}. Feature '{}' disabled.",
                description, e, feature_name
            );
            println!(
                "cargo:warning=  Install {} development package to enable this feature.",
                pkg_name
            );
        }
    }
}

/// Detects DNSSEC cryptography libraries (nettle + hogweed).
///
/// DNSSEC requires both nettle (for general crypto) and hogweed (for
/// public-key crypto). Both must be present to enable DNSSEC validation.
///
/// This matches Makefile lines 65-70:
/// ```make
/// nettle_cflags = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_DNSSEC $(PKG_CONFIG) --cflags 'nettle hogweed' ...`
/// nettle_libs =   `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_DNSSEC $(PKG_CONFIG) --libs 'nettle hogweed' ...`
/// ```
fn detect_dnssec_libraries() {
    let nettle_result = pkg_config::probe_library("nettle");
    let hogweed_result = pkg_config::probe_library("hogweed");
    
    match (nettle_result, hogweed_result) {
        (Ok(nettle), Ok(hogweed)) => {
            // Both libraries found - enable DNSSEC
            println!("cargo:rustc-cfg=feature=\"dnssec\"");
            println!(
                "cargo:warning=✓ DNSSEC support enabled (nettle {}, hogweed {})",
                nettle.version, hogweed.version
            );
            
            // Also check for GMP (GNU Multi-Precision) library for big integer math
            // Makefile line 71: gmp_libs = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_DNSSEC NO_GMP --copy -lgmp`
            if pkg_config::probe_library("gmp").is_ok() {
                println!("cargo:warning=  ✓ GMP library detected for optimized arithmetic");
            } else {
                println!("cargo:warning=  ℹ GMP library not found (using fallback arithmetic)");
            }
        }
        (Err(e1), _) => {
            println!("cargo:warning=✗ DNSSEC disabled: nettle library not found ({})", e1);
            println!("cargo:warning=  Install libnettle-dev or nettle-devel to enable DNSSEC");
        }
        (_, Err(e2)) => {
            println!("cargo:warning=✗ DNSSEC disabled: hogweed library not found ({})", e2);
            println!("cargo:warning=  Install libhogweed-dev or nettle-devel to enable DNSSEC");
        }
    }
}

/// Detects `OpenWrt` ubus libraries (libubus + libubox).
///
/// This matches Makefile line 56:
/// ```make
/// ubus_libs = `echo $(COPTS) | $(top)/bld/pkg-wrapper HAVE_UBUS "" --copy '-lubox -lubus'`
/// ```
///
/// Note: ubus uses --copy mode in pkg-wrapper (direct library linking without pkg-config),
/// so we manually link the libraries if they can be found.
fn detect_ubus_libraries() {
    // ubus doesn't always provide pkg-config files, so we try pkg-config first,
    // then fall back to direct library detection
    
    let ubus_available = pkg_config::probe_library("libubus").is_ok()
        || library_exists("ubus");
    let ubox_available = pkg_config::probe_library("libubox").is_ok()
        || library_exists("ubox");
    
    if ubus_available && ubox_available {
        println!("cargo:rustc-cfg=feature=\"ubus\"");
        println!("cargo:rustc-link-lib=dylib=ubus");
        println!("cargo:rustc-link-lib=dylib=ubox");
        println!("cargo:warning=✓ OpenWrt ubus integration enabled");
    } else {
        println!("cargo:warning=✗ OpenWrt ubus not found (requires libubus and libubox)");
        println!("cargo:warning=  This is expected on non-OpenWrt systems");
    }
}

/// Checks if a library exists in the linker search path.
///
/// This is a fallback for libraries that don't provide pkg-config files.
/// Uses a simple heuristic: check common library paths for the library file.
///
/// # Arguments
/// * `lib_name` - Library name without 'lib' prefix (e.g., "ubus" for libubus.so)
///
/// # Returns
/// * `true` if the library can be found
/// * `false` otherwise
fn library_exists(lib_name: &str) -> bool {
    // Common library search paths on Unix-like systems
    let lib_paths = [
        "/usr/lib",
        "/usr/local/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib64",
        "/lib",
        "/lib64",
    ];
    
    // Check for .so, .a, or .dylib extensions
    let lib_extensions = ["so", "a", "dylib"];
    
    for path in &lib_paths {
        for ext in &lib_extensions {
            let lib_file = format!("{}/lib{}.{}", path, lib_name, ext);
            if Path::new(&lib_file).exists() {
                return true;
            }
        }
    }
    
    false
}

/// Stamps version information into the build.
///
/// This replicates Makefile line 75:
/// ```make
/// version = -DVERSION='\"`$(top)/bld/get-version $(top)`\"'
/// ```
///
/// Version is determined from:
/// 1. VERSION file in repository root (if present)
/// 2. `git describe --tags` output (if in git repository)
/// 3. Fallback to "unknown" if neither available
///
/// The version is exposed via `DNSMASQ_VERSION` environment variable
/// during compilation, accessible as `env!("DNSMASQ_VERSION")`.
fn stamp_version() {
    let version = get_version();
    println!("cargo:rustc-env=DNSMASQ_VERSION={}", version);
    println!("cargo:warning=Building dnsmasq version {}", version);
}

/// Determines the version string for this build.
///
/// Tries multiple strategies in order:
/// 1. Read VERSION file if it exists and contains a real version (not a git substitution marker)
/// 2. Run `git describe --tags` if in a git repository
/// 3. Use "unknown" as fallback
///
/// # Returns
/// Version string (e.g., "2.90" or "2.90-rc1-5-g1234abc")
fn get_version() -> String {
    // Strategy 1: Read VERSION file
    if let Ok(version) = fs::read_to_string("VERSION") {
        let version = version.trim();
        // Check if it's a real version (not a git export substitution marker)
        if !version.is_empty() && !version.starts_with("$Format:") {
            return version.to_string();
        }
    }
    
    // Strategy 2: Use git describe
    if let Ok(output) = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
    {
        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout);
            let version = version.trim();
            if !version.is_empty() {
                return version.to_string();
            }
        }
    }
    
    // Strategy 3: Fallback
    println!("cargo:warning=Could not determine version (no VERSION file or git repository)");
    "unknown".to_string()
}
