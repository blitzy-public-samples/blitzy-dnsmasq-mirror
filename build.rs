//! Build script for dnsmasq
//!
//! This script performs feature detection and links external libraries.

use pkg_config;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    // Detect platform
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-cfg=platform=\"linux\"");
            
            // Optional dependency detection (similar to C Makefile)
            if pkg_config::probe_library("dbus-1").is_ok() {
                println!("cargo:rustc-cfg=have_dbus");
            }
            
            if pkg_config::probe_library("libidn2").is_ok() {
                println!("cargo:rustc-cfg=have_idn2");
            }
            
            if pkg_config::probe_library("nettle").is_ok() && pkg_config::probe_library("hogweed").is_ok() {
                println!("cargo:rustc-cfg=have_dnssec_libs");
            }
            
            if pkg_config::probe_library("libnetfilter_conntrack").is_ok() {
                println!("cargo:rustc-cfg=have_conntrack");
            }
            
            if pkg_config::probe_library("libnftables").is_ok() {
                println!("cargo:rustc-cfg=have_nftables");
            }
        }
        "freebsd" | "openbsd" | "netbsd" => {
            println!("cargo:rustc-cfg=platform=\"bsd\"");
        }
        "macos" => {
            println!("cargo:rustc-cfg=platform=\"macos\"");
        }
        _ => {}
    }
}
