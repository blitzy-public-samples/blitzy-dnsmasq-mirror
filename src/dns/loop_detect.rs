// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS forwarding loop detection
//
// Translated from: src/loop.c

//! DNS forwarding loop detection
//!
//! Detects and prevents DNS forwarding loops where queries would be
//! sent back to dnsmasq itself, creating infinite forwarding loops.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Loop detector for DNS forwarding
#[derive(Debug)]
pub struct LoopDetector {
    local_addresses: HashSet<IpAddr>,
    checked_addresses: HashSet<IpAddr>,
}

impl LoopDetector {
    /// Create a new loop detector
    pub fn new() -> Self {
        Self {
            local_addresses: HashSet::new(),
            checked_addresses: HashSet::new(),
        }
    }

    /// Add a local address (this server's address)
    pub fn add_local_address(&mut self, addr: IpAddr) {
        self.local_addresses.insert(addr);
    }

    /// Check if an address would create a forwarding loop
    pub fn is_loop(&self, addr: &IpAddr) -> bool {
        self.local_addresses.contains(addr)
    }

    /// Check if an address is localhost
    pub fn is_localhost(addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(ipv4) => ipv4.is_loopback(),
            IpAddr::V6(ipv6) => ipv6.is_loopback(),
        }
    }

    /// Mark an address as checked
    pub fn mark_checked(&mut self, addr: IpAddr) {
        self.checked_addresses.insert(addr);
    }

    /// Check if an address has been checked
    pub fn is_checked(&self, addr: &IpAddr) -> bool {
        self.checked_addresses.contains(addr)
    }

    /// Clear the checked addresses cache
    pub fn clear_checked(&mut self) {
        self.checked_addresses.clear();
    }

    /// Get the number of local addresses
    pub fn local_address_count(&self) -> usize {
        self.local_addresses.len()
    }
}

impl Default for LoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loop_detector_creation() {
        let detector = LoopDetector::new();
        assert_eq!(detector.local_address_count(), 0);
    }

    #[test]
    fn test_add_local_address() {
        let mut detector = LoopDetector::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        detector.add_local_address(addr);
        assert_eq!(detector.local_address_count(), 1);
        assert!(detector.is_loop(&addr));
    }

    #[test]
    fn test_is_loop() {
        let mut detector = LoopDetector::new();
        let local_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let remote_addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        detector.add_local_address(local_addr);

        assert!(detector.is_loop(&local_addr));
        assert!(!detector.is_loop(&remote_addr));
    }

    #[test]
    fn test_is_localhost() {
        assert!(LoopDetector::is_localhost(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(LoopDetector::is_localhost(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!LoopDetector::is_localhost(&IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
    }

    #[test]
    fn test_mark_and_check() {
        let mut detector = LoopDetector::new();
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        assert!(!detector.is_checked(&addr));
        detector.mark_checked(addr);
        assert!(detector.is_checked(&addr));
    }

    #[test]
    fn test_clear_checked() {
        let mut detector = LoopDetector::new();
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        detector.mark_checked(addr);
        assert!(detector.is_checked(&addr));

        detector.clear_checked();
        assert!(!detector.is_checked(&addr));
    }
}
