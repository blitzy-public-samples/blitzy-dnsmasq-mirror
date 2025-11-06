// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! IPv6 Address Classification Utilities
//!
//! This module provides type-safe Rust equivalents of C macros from `src/ip6addr.h`,
//! implementing IPv6 address classification methods for Unique Local Addresses (ULA)
//! and link-local address detection.
//!
//! # Purpose
//!
//! The C implementation uses preprocessor macros that perform unsafe pointer casting
//! to treat `struct in6_addr` as arrays of `uint32_t` words. This Rust implementation
//! provides the same functionality using safe methods on `std::net::Ipv6Addr`, eliminating:
//!
//! - Unsafe pointer casting (`(__const uint32_t *) (a)`)
//! - Platform-specific `struct in6_addr` representations
//! - Manual byte-order conversions with `htonl()`
//!
//! Instead, we use `Ipv6Addr::octets()` which returns a byte array `[u8; 16]`, providing
//! portable, bounds-checked access to address bytes across all platforms.
//!
//! # RFCs Implemented
//!
//! - **RFC 4193**: Unique Local IPv6 Unicast Addresses (ULA, fd00::/8)
//! - **RFC 4291**: IPv6 Addressing Architecture (link-local fe80::/10)
//!
//! # Usage in dnsmasq
//!
//! ## DHCPv6 Address Validation (`dhcp::v6`)
//!
//! ```rust,ignore
//! use crate::ipv6::addr::Ipv6AddrExt;
//! use std::net::Ipv6Addr;
//!
//! let addr: Ipv6Addr = "fd12:3456:789a::1".parse()?;
//! if addr.is_ula() {
//!     // Address is in ULA range, valid for DHCPv6 private pool
//!     println!("DHCPv6 assigning ULA address");
//! }
//! ```
//!
//! ## Router Advertisement Prefix Checks (`ipv6::radv`)
//!
//! ```rust,ignore
//! let prefix: Ipv6Addr = "fd00::".parse()?;
//! if prefix.is_ula_zero() {
//!     // Exact fd00:: prefix boundary, not a host address
//!     warn!("RA prefix is ULA boundary address");
//! }
//! ```
//!
//! ## SLAAC Address Generation (`ipv6::slaac`)
//!
//! ```rust,ignore
//! let link_local: Ipv6Addr = "fe80::".parse()?;
//! if link_local.is_link_local_zero() {
//!     // Link-local prefix without interface identifier
//!     warn!("Link-local address missing interface ID");
//! }
//! ```
//!
//! # Memory Safety
//!
//! This module demonstrates the memory safety benefits of the C-to-Rust refactor:
//!
//! | C Implementation | Rust Implementation | Safety Improvement |
//! |------------------|---------------------|-------------------|
//! | `((__const uint32_t *) (a))[0]` | `octets()[0]` | No pointer casting |
//! | `htonl(0xfd000000)` | `0xfd` direct comparison | No byte-order issues |
//! | Manual bounds checking | Automatic slice bounds | No buffer overruns |
//! | NULL pointer checks | `Option<T>` types | No null dereferences |
//!
//! # Performance
//!
//! - **is_ula()**: Single byte comparison, O(1)
//! - **is_ula_zero()**: 16 byte comparisons (optimized by compiler), O(1)
//! - **is_link_local_zero()**: 16 byte comparisons (optimized by compiler), O(1)
//!
//! All methods are inlined and typically compile to the same assembly as the C macros.

use std::net::Ipv6Addr;

/// Extension trait for `std::net::Ipv6Addr` providing IPv6 address classification methods.
///
/// This trait adds methods to `Ipv6Addr` for detecting Unique Local Addresses (ULA)
/// and link-local addresses, matching the behavior of C macros from `src/ip6addr.h`.
///
/// # Examples
///
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::ipv6::addr::Ipv6AddrExt;
///
/// let ula: Ipv6Addr = "fd12:3456::1".parse().unwrap();
/// assert!(ula.is_ula());
/// assert!(!ula.is_ula_zero());
///
/// let ula_prefix: Ipv6Addr = "fd00::".parse().unwrap();
/// assert!(ula_prefix.is_ula());
/// assert!(ula_prefix.is_ula_zero());
///
/// let link_local_prefix: Ipv6Addr = "fe80::".parse().unwrap();
/// assert!(link_local_prefix.is_link_local_zero());
/// ```
pub trait Ipv6AddrExt {
    /// Check if the IPv6 address is a Unique Local Address (ULA).
    ///
    /// Returns `true` if the address falls within the `fd00::/8` prefix defined by RFC 4193.
    /// ULA addresses are analogous to IPv4 private addresses (RFC 1918) and are not routable
    /// on the global Internet.
    ///
    /// # Implementation Note
    ///
    /// This method checks only the first byte of the address:
    /// - C macro: `(((__const uint32_t *) (a))[0] & htonl(0xff000000)) == htonl(0xfd000000)`
    /// - Rust: `octets()[0] == 0xfd`
    ///
    /// The Rust implementation is simpler and more portable, avoiding pointer casts and
    /// byte-order conversions.
    ///
    /// # RFC Compliance
    ///
    /// - **RFC 4193 Section 3**: ULA addresses use `fc00::/7` prefix
    /// - This implementation matches only `fd00::/8` (L=1 bit, locally assigned)
    /// - Does not match `fc00::/8` (L=0 bit, reserved for future central assignment)
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::ipv6::addr::Ipv6AddrExt;
    ///
    /// let ula: Ipv6Addr = "fd12:3456:789a::1".parse().unwrap();
    /// assert!(ula.is_ula());
    ///
    /// let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
    /// assert!(!global.is_ula());
    ///
    /// let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    /// assert!(!link_local.is_ula());
    /// ```
    fn is_ula(&self) -> bool;

    /// Check if the IPv6 address is exactly `fd00::` (ULA prefix with all-zero host portion).
    ///
    /// Returns `true` if the address is exactly `fd00:0000:0000:0000:0000:0000:0000:0000`
    /// (abbreviated as `fd00::`). This represents the ULA network prefix boundary, not an
    /// actual host address.
    ///
    /// # Implementation Note
    ///
    /// The C macro performs four 32-bit word comparisons:
    /// ```c
    /// (((__const uint32_t *) (a))[0] == htonl(0xfd000000) &&
    ///  ((__const uint32_t *) (a))[1] == 0 &&
    ///  ((__const uint32_t *) (a))[2] == 0 &&
    ///  ((__const uint32_t *) (a))[3] == 0)
    /// ```
    ///
    /// The Rust implementation checks:
    /// - First byte is `0xfd`
    /// - Bytes 1-15 are all `0x00`
    ///
    /// # Usage
    ///
    /// This is used in DHCPv6 configuration validation to detect when `fd00::` appears as
    /// a placeholder or default prefix value, distinguishing it from actual host addresses
    /// within the ULA range.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::ipv6::addr::Ipv6AddrExt;
    ///
    /// let ula_prefix: Ipv6Addr = "fd00::".parse().unwrap();
    /// assert!(ula_prefix.is_ula_zero());
    /// assert!(ula_prefix.is_ula());  // Also matches general ULA check
    ///
    /// let ula_host: Ipv6Addr = "fd00::1".parse().unwrap();
    /// assert!(!ula_host.is_ula_zero());  // Not the prefix boundary
    /// assert!(ula_host.is_ula());  // Still a ULA address
    ///
    /// let ula_subnet: Ipv6Addr = "fd12::".parse().unwrap();
    /// assert!(!ula_subnet.is_ula_zero());  // Different ULA prefix
    /// ```
    fn is_ula_zero(&self) -> bool;

    /// Check if the IPv6 address is exactly `fe80::` (link-local prefix with all-zero host).
    ///
    /// Returns `true` if the address is exactly `fe80:0000:0000:0000:0000:0000:0000:0000`
    /// (abbreviated as `fe80::`). This represents the link-local address prefix boundary
    /// without an interface identifier.
    ///
    /// # Implementation Note
    ///
    /// The C macro performs:
    /// ```c
    /// (((__const uint32_t *) (a))[0] == htonl(0xfe800000) &&
    ///  ((__const uint32_t *) (a))[1] == 0 &&
    ///  ((__const uint32_t *) (a))[2] == 0 &&
    ///  ((__const uint32_t *) (a))[3] == 0)
    /// ```
    ///
    /// The Rust implementation checks:
    /// - First byte is `0xfe`
    /// - Second byte is `0x80`
    /// - Bytes 2-15 are all `0x00`
    ///
    /// # Link-Local Addresses
    ///
    /// Per RFC 4291 Section 2.5.6, link-local addresses:
    /// - Use the `fe80::/10` prefix
    /// - Are valid only on a single network link
    /// - Should include a 64-bit interface identifier
    ///
    /// The address `fe80::` without an interface identifier is unusual and typically indicates
    /// an uninitialized or placeholder configuration value.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::ipv6::addr::Ipv6AddrExt;
    ///
    /// let link_local_prefix: Ipv6Addr = "fe80::".parse().unwrap();
    /// assert!(link_local_prefix.is_link_local_zero());
    ///
    /// let link_local_host: Ipv6Addr = "fe80::1".parse().unwrap();
    /// assert!(!link_local_host.is_link_local_zero());  // Has interface ID
    ///
    /// let link_local_eui64: Ipv6Addr = "fe80::abcd:ef01:2345:6789".parse().unwrap();
    /// assert!(!link_local_eui64.is_link_local_zero());  // Normal link-local address
    /// ```
    fn is_link_local_zero(&self) -> bool;
}

impl Ipv6AddrExt for Ipv6Addr {
    #[inline]
    fn is_ula(&self) -> bool {
        // Check if first byte is 0xfd (fd00::/8 prefix)
        // Equivalent to C macro: (a[0] & 0xff000000) == 0xfd000000
        self.octets()[0] == 0xfd
    }

    #[inline]
    fn is_ula_zero(&self) -> bool {
        let octets = self.octets();
        // Check for exactly fd00::
        // First byte must be 0xfd, all other bytes must be 0x00
        octets[0] == 0xfd && octets[1..].iter().all(|&b| b == 0)
    }

    #[inline]
    fn is_link_local_zero(&self) -> bool {
        let octets = self.octets();
        // Check for exactly fe80::
        // First byte must be 0xfe, second byte must be 0x80, all others 0x00
        octets[0] == 0xfe && octets[1] == 0x80 && octets[2..].iter().all(|&b| b == 0)
    }
}

// Standalone helper functions for backward compatibility and convenience
// These mirror the function-style usage in some C code

/// Check if an IPv6 address is a Unique Local Address (ULA).
///
/// Convenience function that calls the `Ipv6AddrExt::is_ula()` trait method.
/// Provided for functional-style usage matching C function calls.
///
/// # Examples
///
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::ipv6::addr::is_ula;
///
/// let addr: Ipv6Addr = "fd12:3456::1".parse().unwrap();
/// assert!(is_ula(&addr));
/// ```
#[inline]
pub fn is_ula(addr: &Ipv6Addr) -> bool {
    addr.is_ula()
}

/// Check if an IPv6 address is exactly `fd00::`.
///
/// Convenience function that calls the `Ipv6AddrExt::is_ula_zero()` trait method.
///
/// # Examples
///
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::ipv6::addr::is_ula_zero;
///
/// let addr: Ipv6Addr = "fd00::".parse().unwrap();
/// assert!(is_ula_zero(&addr));
/// ```
#[inline]
pub fn is_ula_zero(addr: &Ipv6Addr) -> bool {
    addr.is_ula_zero()
}

/// Check if an IPv6 address is exactly `fe80::`.
///
/// Convenience function that calls the `Ipv6AddrExt::is_link_local_zero()` trait method.
///
/// # Examples
///
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::ipv6::addr::is_link_local_zero;
///
/// let addr: Ipv6Addr = "fe80::".parse().unwrap();
/// assert!(is_link_local_zero(&addr));
/// ```
#[inline]
pub fn is_link_local_zero(addr: &Ipv6Addr) -> bool {
    addr.is_link_local_zero()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ula() {
        // Test ULA addresses (fd00::/8)
        let ula1: Ipv6Addr = "fd00::".parse().unwrap();
        assert!(ula1.is_ula());

        let ula2: Ipv6Addr = "fd12:3456:789a::1".parse().unwrap();
        assert!(ula2.is_ula());

        let ula3: Ipv6Addr = "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        assert!(ula3.is_ula());

        // Test non-ULA addresses
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!global.is_ula());

        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(!link_local.is_ula());

        let loopback: Ipv6Addr = "::1".parse().unwrap();
        assert!(!loopback.is_ula());

        let multicast: Ipv6Addr = "ff02::1".parse().unwrap();
        assert!(!multicast.is_ula());

        // fc00::/8 should NOT match (L=0 bit, reserved)
        let fc_range: Ipv6Addr = "fc00::1".parse().unwrap();
        assert!(!fc_range.is_ula());
    }

    #[test]
    fn test_is_ula_zero() {
        // Test exact fd00::
        let ula_zero: Ipv6Addr = "fd00::".parse().unwrap();
        assert!(ula_zero.is_ula_zero());
        assert!(ula_zero.is_ula());  // Should also match general ULA check

        // Test non-matching addresses
        let ula_one: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(!ula_one.is_ula_zero());
        assert!(ula_one.is_ula());  // Still ULA, just not zero

        let ula_subnet: Ipv6Addr = "fd12::".parse().unwrap();
        assert!(!ula_subnet.is_ula_zero());
        assert!(ula_subnet.is_ula());

        let global: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(!global.is_ula_zero());
    }

    #[test]
    fn test_is_link_local_zero() {
        // Test exact fe80::
        let ll_zero: Ipv6Addr = "fe80::".parse().unwrap();
        assert!(ll_zero.is_link_local_zero());

        // Test non-matching link-local addresses
        let ll_one: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(!ll_one.is_link_local_zero());

        let ll_eui64: Ipv6Addr = "fe80::abcd:ef01:2345:6789".parse().unwrap();
        assert!(!ll_eui64.is_link_local_zero());

        // Test non-link-local addresses
        let global: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(!global.is_link_local_zero());

        let ula: Ipv6Addr = "fd00::".parse().unwrap();
        assert!(!ula.is_link_local_zero());
    }

    #[test]
    fn test_standalone_functions() {
        // Test that standalone functions work the same as trait methods
        let ula: Ipv6Addr = "fd12::1".parse().unwrap();
        assert_eq!(is_ula(&ula), ula.is_ula());

        let ula_zero: Ipv6Addr = "fd00::".parse().unwrap();
        assert_eq!(is_ula_zero(&ula_zero), ula_zero.is_ula_zero());

        let ll_zero: Ipv6Addr = "fe80::".parse().unwrap();
        assert_eq!(is_link_local_zero(&ll_zero), ll_zero.is_link_local_zero());
    }

    #[test]
    fn test_c_macro_equivalence() {
        // Verify exact behavior match with C macros from examples in ip6addr.h

        // Example from IN6_IS_ADDR_ULA documentation
        let addr1: Ipv6Addr = "fd12:3456:789a:1::1".parse().unwrap();
        assert!(addr1.is_ula());

        // Example from IN6_IS_ADDR_ULA_ZERO documentation
        let addr2: Ipv6Addr = "fd00::".parse().unwrap();
        assert!(addr2.is_ula_zero());

        // Example from IN6_IS_ADDR_LINK_LOCAL_ZERO documentation
        let addr3: Ipv6Addr = "fe80::".parse().unwrap();
        assert!(addr3.is_link_local_zero());
    }
}
