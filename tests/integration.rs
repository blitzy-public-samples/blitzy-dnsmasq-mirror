// Copyright (C) 2024 Blitzy Platform - dnsmasq Rust Port
// This file is part of the dnsmasq Rust implementation.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Integration test module loader
//!
//! This file makes the integration/ subdirectory's tests discoverable by cargo test.
//! In Rust, integration tests need to be either:
//! 1. Direct files under tests/ directory (e.g., tests/my_test.rs)
//! 2. Modules referenced from a top-level test file
//!
//! This file uses approach #2 to maintain the organized directory structure
//! specified in the Agent Action Plan (Section 0.3.1).

mod integration {
    pub mod config_tests;
    pub mod dhcp_tests;
    pub mod dns_tests;
    pub mod lease_tests;
    pub mod platform_tests;
    pub mod tftp_tests;
}
