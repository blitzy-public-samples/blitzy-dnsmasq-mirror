//! dnsmasq-rs: Rust implementation of dnsmasq
//!
//! Memory-safe Rust implementation of dnsmasq network services daemon providing
//! DNS, DHCP, TFTP, and router advertisement services.

#![allow(unused)]

// Core constants module - fully implemented
pub mod constants;

// Common types and error handling
pub mod types;

// Configuration management
pub mod config;

// Runtime module - daemon lifecycle and event loop
pub mod runtime;

// Integration module - external system services (D-Bus, ubus, scripts)
pub mod integration;

// DNS subsystem - Domain Name System server and forwarder
#[cfg(feature = "dns")]
pub mod dns;

// DHCP subsystem - Dynamic Host Configuration Protocol servers
#[cfg(feature = "dhcp")]
pub mod dhcp;

// TFTP subsystem - Trivial File Transfer Protocol server
#[cfg(feature = "tftp")]
pub mod tftp;

// Network interface enumeration and management
pub mod network;

// Platform-specific implementations
pub mod platform;

// Utility functions and helpers
pub mod util;
