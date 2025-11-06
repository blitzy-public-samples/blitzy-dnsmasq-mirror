// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # IPv6 Router Advertisement and SLAAC
//!
//! This module provides IPv6 Router Advertisement (RA) and Stateless Address
//! Autoconfiguration (SLAAC) functionality, replacing `src/radv.c` and `src/slaac.c`.
//!
//! ## Purpose
//!
//! - IPv6 Router Advertisement transmission (RFC 4861)
//! - Prefix advertisement for SLAAC
//! - Router lifetime management
//! - Recursive DNS Server (RDNSS) option (RFC 6106)
//! - DNS Search List (DNSSL) option (RFC 6106)
//!
//! ## C Source Mapping
//!
//! | C File | Rust Module | Purpose |
//! |--------|-------------|---------|
//! | src/radv.c | radv.rs | Router Advertisement transmission |
//! | src/slaac.c | slaac.rs | SLAAC address tracking |

pub mod radv;
pub mod slaac;

pub use radv::{RouterAdvertiser, RouterAdvertisement, PrefixInfo};
pub use slaac::{SlaacManager, SlaacAddress};
