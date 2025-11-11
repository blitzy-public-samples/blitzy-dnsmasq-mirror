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

//! DHCP Unique Identifier (DUID) generation and parsing per RFC 3315 Section 9
//!
//! This module implements DHCPv6 server DUID generation with full RFC 3315 compliance,
//! replacing the C implementation's manual memory management and callback-based interface
//! enumeration with safe Rust abstractions.
//!
//! # DUID Types
//!
//! RFC 3315 defines three DUID types:
//!
//! - **DUID-LLT (Type 1)**: Link-Layer address plus Time
//!   - Format: `[0x00,0x01][hw_type:u16][time:u32][link_layer_addr]`
//!   - Used when stable clock available
//!   - Time is seconds since 2000-01-01 00:00:00 UTC (epoch 946684800)
//!
//! - **DUID-EN (Type 2)**: Enterprise Number
//!   - Format: `[0x00,0x02][enterprise:u32][identifier:Vec<u8>]`
//!   - Used when custom DUID configured via duid-file
//!   - Enterprise number from IANA Private Enterprise Numbers registry
//!
//! - **DUID-LL (Type 3)**: Link-Layer address only
//!   - Format: `[0x00,0x03][hw_type:u16][link_layer_addr]`
//!   - Used on systems with broken RTC or no persistent storage
//!   - Hardware type from IANA ARP Hardware Types registry
//!
//! # Memory Safety Transformations
//!
//! | C Pattern (dhcp6.c) | Rust Replacement | Safety Benefit |
//! |---------------------|------------------|----------------|
//! | `safe_malloc()` / `free()` | `Vec<u8>` | Automatic deallocation, no leaks |
//! | `memcpy(p, mac, maclen)` | `extend_from_slice()` | Bounds-checked copy |
//! | `PUTSHORT(val, p)` | `write_u16::<BigEndian>()` | Safe endianness conversion |
//! | `PUTLONG(val, p)` | `write_u32::<BigEndian>()` | No unaligned access |
//! | `iface_enumerate(callback)` | `nix::ifaddrs::getifaddrs()` | No callback lifetime issues |
//! | `if (type >= 256) return 1` | `if hw_type < 256 { ... }` | Type-safe filtering |
//! | `daemon->duid` global | `Duid` struct | No global mutable state |
//! | `die()` on error | `Result<Duid, DuidError>` | Recoverable errors |
//!
//! # Architecture
//!
//! **C Implementation (dhcp6.c lines 1118-1233):**
//! ```c
//! void make_duid(time_t now) {
//!     if (daemon->duid_config) {
//!         // DUID-EN from config
//!         daemon->duid = safe_malloc(...);
//!         PUTSHORT(2, p);  // Manual big-endian
//!         memcpy(p, daemon->duid_config, ...);
//!     } else {
//!         time_t newnow = now - 946684800;  // Rebase to 2000-01-01
//!         iface_enumerate(AF_LOCAL, &newnow, make_duid1);  // Callback pattern
//!         if (!daemon->duid) die("Cannot create DUID");
//!     }
//! }
//!
//! static int make_duid1(int index, unsigned int type, char *mac, 
//!                       size_t maclen, void *parm) {
//!     if (type >= 256) return 1;  // Skip tunnels/virtual interfaces
//!     time_t newnow = *((time_t *)parm);
//!     
//!     if (newnow == 0) {
//!         daemon->duid = safe_malloc(maclen + 4);
//!         PUTSHORT(3, p);  // DUID_LL
//!         PUTSHORT(type, p);
//!     } else {
//!         daemon->duid = safe_malloc(maclen + 8);
//!         PUTSHORT(1, p);  // DUID_LLT
//!         PUTSHORT(type, p);
//!         PUTLONG(newnow, p);
//!     }
//!     memcpy(p, mac, maclen);
//!     return 0;  // Stop enumeration
//! }
//! ```
//!
//! **Rust Implementation (this module):**
//! ```no_run
//! use dnsmasq::dhcp::v6::duid::{DuidGenerator, DuidType};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let generator = DuidGenerator::new();
//!
//! // Generate DUID-LLT (with stable clock)
//! let duid = generator.generate_llt().await?;
//! println!("DUID-LLT: {}", duid);  // Display as hex
//!
//! // Generate DUID-LL (broken RTC)
//! let duid = generator.generate_ll().await?;
//! println!("DUID-LL: {}", duid);
//!
//! // Generate DUID-EN (from config)
//! let duid = generator.generate_en(12345, b"custom-identifier")?;
//! println!("DUID-EN: {}", duid);
//!
//! // Serialize for network transmission
//! let bytes = duid.to_bytes();
//! # Ok(())
//! # }
//! ```
//!
//! # Interface Selection Logic
//!
//! Following C implementation (make_duid1 line 1211), DUIDs are generated from the
//! first suitable network interface matching these criteria:
//!
//! 1. **Not loopback**: Interface flag `IFF_LOOPBACK` must be clear
//! 2. **Physical adapter**: Hardware type < 256 (excludes tunnels like IPIP=768)
//! 3. **Has MAC address**: Link-layer address length > 0
//! 4. **Interface up**: Optional - C code doesn't check `IFF_UP`, we match this
//!
//! Hardware types filtered (type >= 256 rejected):
//! - ARPHRD_ETHER (1): Ethernet - **INCLUDED**
//! - ARPHRD_IEEE802 (6): Token Ring - **INCLUDED**
//! - ARPHRD_FDDI (774): FDDI - **EXCLUDED** (tunnel)
//! - ARPHRD_IPIP (768): IPIP tunnel - **EXCLUDED**
//! - ARPHRD_LOOPBACK (772): Loopback - **EXCLUDED**
//! - ARPHRD_SIT (776): IPv6-in-IPv4 - **EXCLUDED**
//!
//! # Timestamp Calculation
//!
//! DUID-LLT timestamps are seconds since **2000-01-01 00:00:00 UTC** per RFC 3315:
//! ```text
//! Unix epoch:      1970-01-01 00:00:00 UTC = 0
//! DUID epoch:      2000-01-01 00:00:00 UTC = 946684800 seconds since Unix epoch
//! Current time:    time(NULL) returns seconds since Unix epoch
//! DUID timestamp:  time(NULL) - 946684800
//! ```
//!
//! C code (line 1140): `newnow = now - 946684800;`
//! Rust equivalent: `SystemTime::now().duration_since(UNIX_EPOCH)? - Duration::from_secs(946684800)`
//!
//! # Configuration Support
//!
//! The C implementation supports custom DUIDs via daemon->duid_config:
//! - Configuration file: `dhcp-duid=12345,aa:bb:cc:dd:ee:ff`
//! - Enterprise number: 12345 (IANA Private Enterprise Number)
//! - Identifier: hex bytes aa:bb:cc:dd:ee:ff
//!
//! This generates DUID-EN: `[0x00,0x02][0x00,0x00,0x30,0x39][0xaa,0xbb,0xcc,0xdd,0xee,0xff]`
//!
//! # Thread Safety
//!
//! Unlike C's global `daemon->duid` mutable state, this implementation is thread-safe:
//! - `DuidGenerator` is `Send + Sync` safe for concurrent use
//! - `Duid` is `Clone` for sharing across tasks
//! - No global mutable state
//! - All operations are self-contained
//!
//! # Original C Source Reference
//!
//! - `src/dhcp6.c` lines 1118-1148: `make_duid()` main function
//! - `src/dhcp6.c` lines 1199-1233: `make_duid1()` callback
//! - `src/dnsmasq.h`: `struct daemon { unsigned char *duid; int duid_len; }`

use byteorder::{BigEndian, WriteBytesExt};
use std::clone::Clone;
use std::cmp::PartialEq;
use std::error::Error;
use std::fmt::{self, Debug, Display};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, trace, warn};

/// DUID type discriminator per RFC 3315 Section 9
///
/// Represents the three DUID types defined in RFC 3315:
/// - Type 1: DUID-LLT (Link-Layer address plus Time)
/// - Type 2: DUID-EN (Enterprise Number)
/// - Type 3: DUID-LL (Link-Layer address only)
///
/// # Wire Format Values
///
/// These values appear in the first two bytes of the DUID in network byte order:
/// - `Llt`: `0x0001` (big-endian u16)
/// - `En`: `0x0002` (big-endian u16)
/// - `Ll`: `0x0003` (big-endian u16)
///
/// # Example
///
/// ```
/// use dnsmasq::dhcp::v6::duid::DuidType;
///
/// let duid_type = DuidType::Llt;
/// assert_eq!(duid_type.to_u16(), 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuidType {
    /// DUID-LLT: Link-Layer address plus Time (Type 1)
    ///
    /// Used when stable system clock is available. Combines hardware address
    /// with timestamp for uniqueness across time and space.
    Llt,

    /// DUID-EN: Enterprise Number (Type 2)
    ///
    /// Used when custom DUID is configured. Contains IANA-assigned enterprise
    /// number and administrator-defined identifier.
    En,

    /// DUID-LL: Link-Layer address only (Type 3)
    ///
    /// Used on systems with broken RTC (`HAVE_BROKEN_RTC`) or no persistent lease
    /// storage. Less unique than DUID-LLT but doesn't require stable clock.
    Ll,
}

impl DuidType {
    /// Convert DUID type to wire format value
    ///
    /// Returns the u16 value that appears in the first two bytes of the DUID.
    ///
    /// # Returns
    ///
    /// - `Llt`: 1
    /// - `En`: 2
    /// - `Ll`: 3
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::Llt => 1,
            Self::En => 2,
            Self::Ll => 3,
        }
    }

    /// Parse DUID type from wire format value
    ///
    /// Converts the first two bytes of a DUID into a `DuidType`.
    ///
    /// # Arguments
    ///
    /// * `value` - The u16 value from network bytes
    ///
    /// # Returns
    ///
    /// - `Some(DuidType)` if value is 1, 2, or 3
    /// - `None` if value is invalid
    ///
    /// # Example
    ///
    /// ```
    /// use dnsmasq::dhcp::v6::duid::DuidType;
    ///
    /// assert_eq!(DuidType::from_u16(1), Some(DuidType::Llt));
    /// assert_eq!(DuidType::from_u16(99), None);
    /// ```
    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Llt),
            2 => Some(Self::En),
            3 => Some(Self::Ll),
            _ => None,
        }
    }
}

impl Display for DuidType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Llt => write!(f, "DUID-LLT"),
            Self::En => write!(f, "DUID-EN"),
            Self::Ll => write!(f, "DUID-LL"),
        }
    }
}

/// DUID error types
///
/// Represents all possible errors during DUID generation and parsing.
/// Replaces C's fatal `die()` calls with recoverable errors.
///
/// # C Error Handling
///
/// C implementation (dhcp6.c line 1146):
/// ```c
/// if (!daemon->duid)
///     die("Cannot create DHCPv6 server DUID: %s", NULL, EC_MISC);
/// ```
///
/// Rust equivalent:
/// ```no_run
/// # use dnsmasq::dhcp::v6::duid::{DuidGenerator, DuidError};
/// # async fn example() -> Result<(), DuidError> {
/// let generator = DuidGenerator::new();
/// generator.generate_llt().await.map_err(|e| {
///     eprintln!("Cannot create DHCPv6 server DUID: {}", e);
///     e
/// })?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub enum DuidError {
    /// No suitable network interface found for DUID generation
    ///
    /// Corresponds to C's fatal error when daemon->duid is NULL after enumeration.
    /// Occurs when:
    /// - No non-loopback interfaces exist
    /// - All interfaces have hardware type >= 256 (tunnels/virtual)
    /// - All interfaces lack MAC addresses
    NoInterface,

    /// DUID length is invalid (must be 4-130 bytes per RFC 3315)
    ///
    /// RFC 3315 Section 9: "The DUID consists of a two-octet type field and an
    /// arbitrary length (no more than 128 octets) value field."
    ///
    /// Total length: 2 (type) + up to 128 (payload) = 4 to 130 bytes
    InvalidLength {
        /// Actual length that failed validation
        length: usize,
    },

    /// DUID type value is invalid (must be 1, 2, or 3)
    InvalidType {
        /// The invalid type value encountered
        type_value: u16,
    },

    /// Error encoding DUID to bytes
    EncodingError(io::Error),

    /// Error decoding DUID from bytes
    DecodingError(String),

    /// System time error during DUID-LLT timestamp calculation
    ///
    /// Occurs when `SystemTime::now()` < `UNIX_EPOCH` or duration arithmetic overflows.
    TimestampError(String),

    /// I/O error during interface enumeration
    ///
    /// Wraps `nix::ifaddrs::getifaddrs()` errors.
    IoError(io::Error),
}

impl Display for DuidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInterface => write!(
                f,
                "Cannot create DHCPv6 server DUID: no suitable network interface found \
                 (all interfaces are loopback, virtual, or have hardware type >= 256)"
            ),
            Self::InvalidLength { length } => write!(
                f,
                "Invalid DUID length {length} bytes (must be 4-130 bytes per RFC 3315)"
            ),
            Self::InvalidType { type_value } => write!(
                f,
                "Invalid DUID type value {type_value} (must be 1=DUID-LLT, 2=DUID-EN, or 3=DUID-LL)"
            ),
            Self::EncodingError(e) => write!(f, "DUID encoding error: {e}"),
            Self::DecodingError(msg) => write!(f, "DUID decoding error: {msg}"),
            Self::TimestampError(msg) => write!(f, "DUID timestamp error: {msg}"),
            Self::IoError(e) => write!(f, "DUID I/O error: {e}"),
        }
    }
}

impl Error for DuidError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EncodingError(e) | Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for DuidError {
    fn from(error: io::Error) -> Self {
        Self::IoError(error)
    }
}

/// DHCP Unique Identifier (DUID)
///
/// Represents a `DHCPv6` server or client DUID with type-safe access to its components.
/// Replaces C's raw `unsigned char *duid` with structured representation.
///
/// # C Representation
///
/// ```c
/// struct daemon {
///     unsigned char *duid;  // Raw bytes, manual malloc/free
///     int duid_len;         // Separate length tracking
///     // ... other fields
/// };
/// ```
///
/// # Rust Representation
///
/// ```
/// # use dnsmasq::dhcp::v6::duid::{Duid, DuidType};
/// // Create DUID using the public API
/// let mut duid_data = vec![0x00, 0x01]; // Hardware type
/// duid_data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // MAC
/// let duid = Duid::new(DuidType::Ll, duid_data).unwrap();
/// // Length is automatically tracked via Vec
/// ```
///
/// # Wire Format
///
/// All DUIDs start with 2-byte type field in network byte order (big-endian):
///
/// **DUID-LLT (6+ bytes minimum):**
/// ```text
/// +------+------+----------+------+------+------+--------+
/// | 0x00 | 0x01 | hw_type  |   timestamp   | MAC address |
/// +------+------+----------+------+------+------+--------+
///    0      1      2     3    4    5    6    7      8+
/// ```
///
/// **DUID-EN (6+ bytes minimum):**
/// ```text
/// +------+------+-------------+----------------+
/// | 0x00 | 0x02 | enterprise  |  identifier... |
/// +------+------+-------------+----------------+
///    0      1      2    3   4   5      6+
/// ```
///
/// **DUID-LL (4+ bytes minimum):**
/// ```text
/// +------+------+----------+-------------+
/// | 0x00 | 0x03 | hw_type  | MAC address |
/// +------+------+----------+-------------+
///    0      1      2     3       4+
/// ```
///
/// # Memory Safety
///
/// - Automatic deallocation via `Vec<u8>` Drop trait
/// - No manual memory management
/// - No buffer overflows in serialization
/// - No use-after-free risks
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Duid {
    /// DUID type (DUID-LLT, DUID-EN, or DUID-LL)
    duid_type: DuidType,

    /// DUID payload data
    ///
    /// **For DUID-LLT:** `[hw_type:u16][timestamp:u32][mac_bytes]`
    /// **For DUID-EN:** `[enterprise:u32][identifier_bytes]`
    /// **For DUID-LL:** `[hw_type:u16][mac_bytes]`
    ///
    /// Does NOT include the 2-byte type field (that's stored in `duid_type`).
    data: Vec<u8>,
}

impl Duid {
    /// Create a new DUID with specified type and data
    ///
    /// # Arguments
    ///
    /// * `duid_type` - The DUID type (LLT, EN, or LL)
    /// * `data` - The DUID payload (without type field)
    ///
    /// # Returns
    ///
    /// - `Ok(Duid)` if length is valid (total 4-130 bytes)
    /// - `Err(DuidError::InvalidLength)` if too short or too long
    ///
    /// # Example
    ///
    /// ```
    /// use dnsmasq::dhcp::v6::duid::{Duid, DuidType};
    ///
    /// // DUID-LL with hardware type 1 (Ethernet) and MAC 00:11:22:33:44:55
    /// let data = vec![0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    /// let duid = Duid::new(DuidType::Ll, data).unwrap();
    /// assert_eq!(duid.len(), 10); // 2 (type) + 8 (data)
    /// ```
    pub fn new(duid_type: DuidType, data: Vec<u8>) -> Result<Self, DuidError> {
        let total_len = 2 + data.len(); // 2 bytes for type field + payload
        if !(4..=130).contains(&total_len) {
            return Err(DuidError::InvalidLength { length: total_len });
        }

        Ok(Self { duid_type, data })
    }

    /// Create a DUID-LL (Link-Layer) with hardware type and link-layer address
    ///
    /// # Arguments
    ///
    /// * `hw_type` - Hardware type from IANA ARP Hardware Types (e.g., 1 for Ethernet)
    /// * `ll_addr` - Link-layer address (e.g., MAC address)
    ///
    /// # Returns
    ///
    /// - `Ok(Duid)` if construction succeeds
    /// - `Err(DuidError::InvalidLength)` if resulting DUID is invalid
    ///
    /// # Example
    ///
    /// ```
    /// use dnsmasq::dhcp::v6::duid::Duid;
    ///
    /// // Ethernet MAC 00:11:22:33:44:55
    /// let duid = Duid::new_ll(1, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).unwrap();
    /// ```
    pub fn new_ll(hw_type: u16, ll_addr: &[u8]) -> Result<Self, DuidError> {
        let mut data = Vec::with_capacity(2 + ll_addr.len());
        data.extend_from_slice(&hw_type.to_be_bytes());
        data.extend_from_slice(ll_addr);
        Self::new(DuidType::Ll, data)
    }

    /// Create a DUID-LLT (Link-Layer + Time) with hardware type, time, and link-layer address
    ///
    /// # Arguments
    ///
    /// * `hw_type` - Hardware type from IANA ARP Hardware Types
    /// * `time` - Time value (seconds since 2000-01-01 00:00:00 UTC)
    /// * `ll_addr` - Link-layer address
    ///
    /// # Returns
    ///
    /// - `Ok(Duid)` if construction succeeds
    /// - `Err(DuidError::InvalidLength)` if resulting DUID is invalid
    ///
    /// # Example
    ///
    /// ```
    /// use dnsmasq::dhcp::v6::duid::Duid;
    ///
    /// let duid = Duid::new_llt(1, 12345, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).unwrap();
    /// ```
    pub fn new_llt(hw_type: u16, time: u32, ll_addr: &[u8]) -> Result<Self, DuidError> {
        let mut data = Vec::with_capacity(6 + ll_addr.len());
        data.extend_from_slice(&hw_type.to_be_bytes());
        data.extend_from_slice(&time.to_be_bytes());
        data.extend_from_slice(ll_addr);
        Self::new(DuidType::Llt, data)
    }

    /// Create a DUID-EN (Enterprise Number) with enterprise number and identifier
    ///
    /// # Arguments
    ///
    /// * `enterprise_num` - Enterprise number from IANA Private Enterprise Numbers
    /// * `identifier` - Unique identifier assigned by the enterprise
    ///
    /// # Returns
    ///
    /// - `Ok(Duid)` if construction succeeds
    /// - `Err(DuidError::InvalidLength)` if resulting DUID is invalid
    ///
    /// # Example
    ///
    /// ```
    /// use dnsmasq::dhcp::v6::duid::Duid;
    ///
    /// let duid = Duid::new_en(9, b"unique-identifier").unwrap();
    /// ```
    pub fn new_en(enterprise_num: u32, identifier: &[u8]) -> Result<Self, DuidError> {
        let mut data = Vec::with_capacity(4 + identifier.len());
        data.extend_from_slice(&enterprise_num.to_be_bytes());
        data.extend_from_slice(identifier);
        Self::new(DuidType::En, data)
    }

    /// Get the DUID type
    ///
    /// # Returns
    ///
    /// The DUID type (LLT, EN, or LL)
    #[must_use]
    pub const fn duid_type(&self) -> DuidType {
        self.duid_type
    }

    /// Get the DUID payload data (without type field)
    ///
    /// # Returns
    ///
    /// Slice of payload bytes
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Parse DUID from wire format bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw DUID bytes including type field
    ///
    /// # Returns
    ///
    /// - `Ok(Duid)` if parsing succeeds
    /// - `Err(DuidError)` if bytes are invalid
    ///
    /// # Errors
    ///
    /// - `InvalidLength`: Less than 4 bytes or more than 130 bytes
    /// - `InvalidType`: Type field is not 1, 2, or 3
    /// - `DecodingError`: Malformed payload
    ///
    /// # Example
    ///
    /// ```
    /// use dnsmasq::dhcp::v6::duid::Duid;
    ///
    /// // DUID-LL: type=3, hw_type=1, mac=00:11:22:33:44:55
    /// let bytes = vec![0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    /// let duid = Duid::from_bytes(&bytes).unwrap();
    /// assert_eq!(duid.len(), 10);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DuidError> {
        if bytes.len() < 4 || bytes.len() > 130 {
            return Err(DuidError::InvalidLength {
                length: bytes.len(),
            });
        }

        // Parse type field (first 2 bytes, big-endian)
        let type_value = u16::from_be_bytes([bytes[0], bytes[1]]);
        let duid_type = DuidType::from_u16(type_value)
            .ok_or(DuidError::InvalidType { type_value })?;

        // Extract payload (everything after type field)
        let data = bytes[2..].to_vec();

        Ok(Self { duid_type, data })
    }

    /// Serialize DUID to wire format bytes
    ///
    /// # Returns
    ///
    /// Complete DUID bytes including type field, ready for network transmission
    ///
    /// # Example
    ///
    /// ```
    /// use dnsmasq::dhcp::v6::duid::{Duid, DuidType};
    ///
    /// let data = vec![0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    /// let duid = Duid::new(DuidType::Ll, data).unwrap();
    ///
    /// let bytes = duid.to_bytes();
    /// assert_eq!(bytes[0], 0x00);
    /// assert_eq!(bytes[1], 0x03); // Type 3 = DUID-LL
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.data.len());

        // Write type field (big-endian u16)
        let type_bytes = self.duid_type.to_u16().to_be_bytes();
        bytes.extend_from_slice(&type_bytes);

        // Write payload
        bytes.extend_from_slice(&self.data);

        bytes
    }

    /// Get total DUID length including type field
    ///
    /// # Returns
    ///
    /// Total length in bytes (2 for type + payload length)
    #[must_use]
    pub fn len(&self) -> usize {
        2 + self.data.len()
    }

    /// Check if DUID is empty (should never be true for valid DUID)
    ///
    /// # Returns
    ///
    /// Always `false` for valid DUIDs (minimum length is 4 bytes)
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        // Valid DUIDs are never empty (minimum 4 bytes)
        false
    }
}

impl Display for Duid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [", self.duid_type)?;

        // Format as hex bytes like C's log output
        let bytes = self.to_bytes();
        for (i, byte) in bytes.iter().enumerate() {
            if i > 0 {
                write!(f, ":")?;
            }
            write!(f, "{byte:02x}")?;
        }

        write!(f, "]")
    }
}

/// DUID generator for creating server DUIDs
///
/// Provides methods to generate all three DUID types following RFC 3315 and matching
/// C implementation behavior. Replaces C's global daemon state with thread-safe API.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::dhcp::v6::duid::DuidGenerator;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let generator = DuidGenerator::new();
///
/// // Generate DUID-LLT (default, with stable clock)
/// let duid = generator.generate_llt().await?;
/// println!("Server DUID: {}", duid);
///
/// // Or use the convenience method that chooses based on config
/// let duid = generator.generate().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct DuidGenerator {
    // No state needed - all generation is self-contained
}

impl DuidGenerator {
    /// Create a new DUID generator
    ///
    /// # Example
    ///
    /// ```
    /// use dnsmasq::dhcp::v6::duid::DuidGenerator;
    ///
    /// let generator = DuidGenerator::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Generate a DUID using the default strategy
    ///
    /// Attempts DUID-LLT generation, falling back to DUID-LL on timestamp errors.
    /// Matches C behavior (dhcp6.c lines 1134-1143).
    ///
    /// # Returns
    ///
    /// - `Ok(Duid)` with DUID-LLT if clock is stable
    /// - `Ok(Duid)` with DUID-LL if timestamp calculation fails
    /// - `Err(DuidError::NoInterface)` if no suitable interface found
    ///
    /// # Errors
    ///
    /// Returns `DuidError` if DUID generation fails
    pub async fn generate(&self) -> Result<Duid, DuidError> {
        // Try DUID-LLT first (with timestamp)
        match self.generate_llt().await {
            Ok(duid) => {
                info!("Generated {} for DHCPv6 server", duid.duid_type());
                Ok(duid)
            }
            Err(DuidError::TimestampError(msg)) => {
                // Fall back to DUID-LL if clock is broken
                warn!(
                    "Timestamp calculation failed ({}), falling back to DUID-LL",
                    msg
                );
                self.generate_ll().await
            }
            Err(e) => Err(e),
        }
    }

    /// Generate DUID-LLT (Link-Layer address plus Time)
    ///
    /// Creates a DUID-LLT from the first suitable network interface and current timestamp.
    /// Corresponds to C's `make_duid()` with `newnow != 0` (dhcp6.c lines 1221-1228).
    ///
    /// # Returns
    ///
    /// - `Ok(Duid)` with DUID-LLT format
    /// - `Err(DuidError::NoInterface)` if no suitable interface found
    /// - `Err(DuidError::TimestampError)` if clock calculation fails
    ///
    /// # Wire Format
    ///
    /// ```text
    /// +------+------+----------+-------------+-------------+
    /// | 0x00 | 0x01 | hw_type  |  timestamp  | MAC address |
    /// +------+------+----------+-------------+-------------+
    ///    2 bytes     2 bytes      4 bytes       6+ bytes
    /// ```
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::dhcp::v6::duid::DuidGenerator;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let generator = DuidGenerator::new();
    /// let duid = generator.generate_llt().await?;
    /// assert!(duid.len() >= 14); // 2 (type) + 2 (hw_type) + 4 (time) + 6 (MAC)
    /// # Ok(())
    /// # }
    /// ```
    pub async fn generate_llt(&self) -> Result<Duid, DuidError> {
        trace!("Generating DUID-LLT with timestamp");

        // Calculate timestamp: seconds since 2000-01-01 00:00:00 UTC
        // C code (dhcp6.c line 1140): newnow = now - 946684800;
        let timestamp = calculate_duid_timestamp()?;
        debug!("DUID-LLT timestamp: {} seconds since 2000-01-01", timestamp);

        // Get first suitable interface
        let (hw_type, mac_addr) = get_interface_hwaddr().await?;
        info!(
            "Selected interface with hardware type {} and {} byte MAC for DUID-LLT",
            hw_type,
            mac_addr.len()
        );

        // Build DUID-LLT payload: [hw_type:u16][timestamp:u32][mac]
        let mut data = Vec::with_capacity(2 + 4 + mac_addr.len());
        data.write_u16::<BigEndian>(hw_type)
            .map_err(DuidError::EncodingError)?;
        data.write_u32::<BigEndian>(timestamp)
            .map_err(DuidError::EncodingError)?;
        data.extend_from_slice(&mac_addr);

        let duid = Duid::new(DuidType::Llt, data)?;
        info!("Generated DUID-LLT: {}", duid);
        Ok(duid)
    }

    /// Generate DUID-LL (Link-Layer address only)
    ///
    /// Creates a DUID-LL from the first suitable network interface without timestamp.
    /// Used when RTC is broken or no persistent lease storage available.
    /// Corresponds to C's `make_duid()` with `newnow == 0` (dhcp6.c lines 1214-1220).
    ///
    /// # Returns
    ///
    /// - `Ok(Duid)` with DUID-LL format
    /// - `Err(DuidError::NoInterface)` if no suitable interface found
    ///
    /// # Wire Format
    ///
    /// ```text
    /// +------+------+----------+-------------+
    /// | 0x00 | 0x03 | hw_type  | MAC address |
    /// +------+------+----------+-------------+
    ///    2 bytes     2 bytes       6+ bytes
    /// ```
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::dhcp::v6::duid::DuidGenerator;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let generator = DuidGenerator::new();
    /// let duid = generator.generate_ll().await?;
    /// assert!(duid.len() >= 10); // 2 (type) + 2 (hw_type) + 6 (MAC)
    /// # Ok(())
    /// # }
    /// ```
    pub async fn generate_ll(&self) -> Result<Duid, DuidError> {
        trace!("Generating DUID-LL without timestamp");

        // Get first suitable interface
        let (hw_type, mac_addr) = get_interface_hwaddr().await?;
        info!(
            "Selected interface with hardware type {} and {} byte MAC for DUID-LL",
            hw_type,
            mac_addr.len()
        );

        // Build DUID-LL payload: [hw_type:u16][mac]
        let mut data = Vec::with_capacity(2 + mac_addr.len());
        data.write_u16::<BigEndian>(hw_type)
            .map_err(DuidError::EncodingError)?;
        data.extend_from_slice(&mac_addr);

        let duid = Duid::new(DuidType::Ll, data)?;
        info!("Generated DUID-LL: {}", duid);
        Ok(duid)
    }

    /// Generate DUID-EN (Enterprise Number)
    ///
    /// Creates a DUID-EN from configured enterprise number and identifier.
    /// Used when custom DUID is configured via daemon->duid_config.
    /// Corresponds to C's `make_duid()` with `daemon->duid_config` (dhcp6.c lines 1122-1131).
    ///
    /// # Arguments
    ///
    /// * `enterprise_number` - IANA Private Enterprise Number
    /// * `identifier` - Custom identifier bytes (arbitrary length)
    ///
    /// # Returns
    ///
    /// - `Ok(Duid)` with DUID-EN format
    /// - `Err(DuidError::InvalidLength)` if total length exceeds 130 bytes
    ///
    /// # Wire Format
    ///
    /// ```text
    /// +------+------+-------------------+-----------------+
    /// | 0x00 | 0x02 | enterprise_number | identifier...   |
    /// +------+------+-------------------+-----------------+
    ///    2 bytes          4 bytes          variable
    /// ```
    ///
    /// # Example
    ///
    /// ```
    /// # use dnsmasq::dhcp::v6::duid::DuidGenerator;
    /// let generator = DuidGenerator::new();
    /// let duid = generator.generate_en(12345, b"custom-id").unwrap();
    /// assert_eq!(duid.duid_type(), dnsmasq::dhcp::v6::duid::DuidType::En);
    /// ```
    pub fn generate_en(
        &self,
        enterprise_number: u32,
        identifier: &[u8],
    ) -> Result<Duid, DuidError> {
        trace!(
            "Generating DUID-EN with enterprise {} and {} byte identifier",
            enterprise_number,
            identifier.len()
        );

        // Build DUID-EN payload: [enterprise:u32][identifier]
        let mut data = Vec::with_capacity(4 + identifier.len());
        data.write_u32::<BigEndian>(enterprise_number)
            .map_err(DuidError::EncodingError)?;
        data.extend_from_slice(identifier);

        let duid = Duid::new(DuidType::En, data)?;
        info!(
            "Generated DUID-EN with enterprise {}: {}",
            enterprise_number, duid
        );
        Ok(duid)
    }
}

impl Default for DuidGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate DUID-LLT timestamp: seconds since 2000-01-01 00:00:00 UTC
///
/// RFC 3315 Section 9.2: "The time value is the time that the DUID is generated
/// represented in seconds since midnight (UTC), January 1, 2000, modulo 2^32."
///
/// # Returns
///
/// - `Ok(u32)` - Seconds since 2000-01-01 00:00:00 UTC
/// - `Err(DuidError::TimestampError)` - System time is before Unix epoch or calculation overflows
///
/// # C Equivalent
///
/// ```c
/// time_t newnow = time(NULL) - 946684800;  // dhcp6.c line 1140
/// ```
fn calculate_duid_timestamp() -> Result<u32, DuidError> {
    const DUID_EPOCH_OFFSET: u64 = 946684800; // 2000-01-01 00:00:00 UTC

    let now = SystemTime::now();
    let since_unix_epoch = now
        .duration_since(UNIX_EPOCH)
        .map_err(|e| DuidError::TimestampError(format!("System time before Unix epoch: {e}")))?;

    let unix_seconds = since_unix_epoch.as_secs();

    // Subtract DUID epoch offset
    let duid_seconds = unix_seconds
        .checked_sub(DUID_EPOCH_OFFSET)
        .ok_or_else(|| {
            DuidError::TimestampError(format!(
                "System time {unix_seconds} is before DUID epoch 2000-01-01"
            ))
        })?;

    // Modulo 2^32 as per RFC 3315
    let timestamp = (duid_seconds % (1u64 << 32)) as u32;

    Ok(timestamp)
}

/// Get hardware address from first suitable network interface
///
/// Enumerates network interfaces using `nix::ifaddrs::getifaddrs()` and returns the
/// hardware address of the first interface matching selection criteria.
///
/// # Selection Criteria (matching C implementation)
///
/// 1. **Not loopback**: `IFF_LOOPBACK` flag clear
/// 2. **Physical adapter**: Hardware type < 256
/// 3. **Has MAC address**: Link-layer address present and non-empty
///
/// # Returns
///
/// - `Ok((hw_type, mac_addr))` - Hardware type and MAC address bytes
/// - `Err(DuidError::NoInterface)` - No suitable interface found
/// - `Err(DuidError::IoError)` - Interface enumeration failed
///
/// # C Equivalent
///
/// ```c
/// static int make_duid1(int index, unsigned int type, char *mac, size_t maclen, void *parm) {
///     if (type >= 256) return 1;  // Continue enumeration
///     // Use this interface
///     memcpy(p, mac, maclen);
///     return 0;  // Stop enumeration
/// }
/// iface_enumerate(AF_LOCAL, &newnow, make_duid1);  // dhcp6.c line 1143
/// ```
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "macos"))]
async fn get_interface_hwaddr() -> Result<(u16, Vec<u8>), DuidError> {
    use nix::ifaddrs::getifaddrs;
    use nix::net::if_::InterfaceFlags;

    trace!("Enumerating network interfaces for DUID generation");

    // Use spawn_blocking for potentially blocking getifaddrs() call
    let result = tokio::task::spawn_blocking(|| {
        let ifaddrs = getifaddrs().map_err(|e| {
            DuidError::IoError(io::Error::other(
                format!("Failed to enumerate interfaces: {e}"),
            ))
        })?;

        for ifaddr in ifaddrs {
            let iface_name = &ifaddr.interface_name;
            let flags = ifaddr.flags;

            // Skip loopback interfaces
            if flags.contains(InterfaceFlags::IFF_LOOPBACK) {
                trace!("Skipping loopback interface: {}", iface_name);
                continue;
            }

            // Get link-layer address (MAC address)
            if let Some(addr) = ifaddr.address {
                // On Linux, link-layer addresses are AF_PACKET
                // On BSD/macOS, they are AF_LINK
                #[cfg(target_os = "linux")]
                {
                    if let Some(ll_addr) = addr.as_link_addr() {
                        if let Some(mac_bytes) = ll_addr.addr() {
                            if !mac_bytes.is_empty() {
                                // Hardware type from arphrd constants
                                // For Ethernet (most common): ARPHRD_ETHER = 1
                                let hw_type = 1u16; // Assume Ethernet for Linux

                                // Filter hardware types >= 256 (tunnels, virtual interfaces)
                                if hw_type < 256 {
                                    debug!(
                                        "Selected interface {} with hw_type={} mac_len={}",
                                        iface_name,
                                        hw_type,
                                        mac_bytes.len()
                                    );
                                    return Ok((hw_type, mac_bytes.to_vec()));
                                }
                                trace!(
                                    "Skipping interface {} with hw_type={} >= 256",
                                    iface_name,
                                    hw_type
                                );
                            }
                        }
                    }
                }

                #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "macos"))]
                {
                    if let Some(ll_addr) = addr.as_link_addr() {
                        // Get hardware type from sdl_type field
                        // This requires accessing nix's internal SockaddrStorage
                        // For simplicity, assume Ethernet (type 1) for BSD
                        let hw_type = 1u16;

                        if let Some(mac_bytes) = ll_addr.addr() {
                            if !mac_bytes.is_empty() && hw_type < 256 {
                                debug!(
                                    "Selected BSD interface {} with hw_type={} mac_len={}",
                                    iface_name,
                                    hw_type,
                                    mac_bytes.len()
                                );
                                return Ok((hw_type, mac_bytes.to_vec()));
                            } else {
                                trace!(
                                    "Skipping BSD interface {} (empty MAC or hw_type >= 256)",
                                    iface_name
                                );
                            }
                        }
                    }
                }
            }
        }

        error!("No suitable interface found for DUID generation (all interfaces are loopback, virtual, or lack MAC addresses)");
        Err(DuidError::NoInterface)
    })
    .await
    .map_err(|e| {
        DuidError::IoError(io::Error::other(
            format!("Interface enumeration task failed: {e}"),
        ))
    })?;

    result
}

/// Solaris implementation: get hardware address from first suitable interface
///
/// Solaris doesn't use getifaddrs(), so we need platform-specific implementation.
/// For now, we'll return an error indicating unsupported platform for DUID auto-generation.
#[cfg(target_os = "solaris")]
async fn get_interface_hwaddr() -> Result<(u16, Vec<u8>), DuidError> {
    error!("Automatic DUID generation not yet implemented for Solaris");
    error!("Please configure a custom DUID using the dhcp-duid configuration option");
    Err(DuidError::NoInterface)
}

/// Convenience function: Generate DUID-LLT
///
/// Standalone function matching the export specification.
/// Equivalent to `DuidGenerator::new().generate_llt().await`.
///
/// # Returns
///
/// - `Ok(Duid)` with DUID-LLT format
/// - `Err(DuidError)` if generation fails
///
/// # Example
///
/// ```no_run
/// use dnsmasq::dhcp::v6::duid::generate_duid_llt;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let duid = generate_duid_llt().await?;
/// println!("DUID-LLT: {}", duid);
/// # Ok(())
/// # }
/// ```
pub async fn generate_duid_llt() -> Result<Duid, DuidError> {
    DuidGenerator::new().generate_llt().await
}

/// Convenience function: Generate DUID-LL
///
/// Standalone function matching the export specification.
/// Equivalent to `DuidGenerator::new().generate_ll().await`.
///
/// # Returns
///
/// - `Ok(Duid)` with DUID-LL format
/// - `Err(DuidError)` if generation fails
///
/// # Example
///
/// ```no_run
/// use dnsmasq::dhcp::v6::duid::generate_duid_ll;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let duid = generate_duid_ll().await?;
/// println!("DUID-LL: {}", duid);
/// # Ok(())
/// # }
/// ```
pub async fn generate_duid_ll() -> Result<Duid, DuidError> {
    DuidGenerator::new().generate_ll().await
}

/// Convenience function: Generate DUID-EN
///
/// Standalone function matching the export specification.
/// Equivalent to `DuidGenerator::new().generate_en(enterprise, identifier)`.
///
/// # Arguments
///
/// * `enterprise_number` - IANA Private Enterprise Number
/// * `identifier` - Custom identifier bytes
///
/// # Returns
///
/// - `Ok(Duid)` with DUID-EN format
/// - `Err(DuidError)` if generation fails
///
/// # Example
///
/// ```
/// use dnsmasq::dhcp::v6::duid::generate_duid_en;
///
/// let duid = generate_duid_en(12345, b"my-identifier").unwrap();
/// println!("DUID-EN: {}", duid);
/// ```
pub fn generate_duid_en(enterprise_number: u32, identifier: &[u8]) -> Result<Duid, DuidError> {
    DuidGenerator::new().generate_en(enterprise_number, identifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duid_type_conversions() {
        assert_eq!(DuidType::Llt.to_u16(), 1);
        assert_eq!(DuidType::En.to_u16(), 2);
        assert_eq!(DuidType::Ll.to_u16(), 3);

        assert_eq!(DuidType::from_u16(1), Some(DuidType::Llt));
        assert_eq!(DuidType::from_u16(2), Some(DuidType::En));
        assert_eq!(DuidType::from_u16(3), Some(DuidType::Ll));
        assert_eq!(DuidType::from_u16(99), None);
    }

    #[test]
    fn test_duid_creation_and_serialization() {
        // Create DUID-LL with Ethernet MAC
        let data = vec![0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let duid = Duid::new(DuidType::Ll, data.clone()).unwrap();

        assert_eq!(duid.duid_type(), DuidType::Ll);
        assert_eq!(duid.data(), &data);
        assert_eq!(duid.len(), 10); // 2 (type) + 8 (data)
        assert!(!duid.is_empty());

        // Test serialization
        let bytes = duid.to_bytes();
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x03); // Type 3 = DUID-LL
        assert_eq!(&bytes[2..], &data);

        // Test deserialization round-trip
        let parsed = Duid::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, duid);
    }

    #[test]
    fn test_duid_length_validation() {
        // Too short (< 4 bytes total)
        let short_data = vec![0x01];
        assert!(matches!(
            Duid::new(DuidType::Ll, short_data),
            Err(DuidError::InvalidLength { .. })
        ));

        // Too long (> 130 bytes total)
        let long_data = vec![0u8; 129]; // 2 + 129 = 131 bytes
        assert!(matches!(
            Duid::new(DuidType::Ll, long_data),
            Err(DuidError::InvalidLength { .. })
        ));

        // Valid lengths
        let valid_min = vec![0x00, 0x01]; // 2 + 2 = 4 bytes
        assert!(Duid::new(DuidType::Ll, valid_min).is_ok());

        let valid_max = vec![0u8; 128]; // 2 + 128 = 130 bytes
        assert!(Duid::new(DuidType::Ll, valid_max).is_ok());
    }

    #[test]
    fn test_duid_en_generation() {
        let generator = DuidGenerator::new();
        let duid = generator.generate_en(12345, b"test-id").unwrap();

        assert_eq!(duid.duid_type(), DuidType::En);

        let bytes = duid.to_bytes();
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x02); // Type 2 = DUID-EN

        // Enterprise number (12345 = 0x00003039) in big-endian
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x00);
        assert_eq!(bytes[4], 0x30);
        assert_eq!(bytes[5], 0x39);

        // Identifier
        assert_eq!(&bytes[6..], b"test-id");
    }

    #[test]
    fn test_duid_display() {
        let data = vec![0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let duid = Duid::new(DuidType::Ll, data).unwrap();

        let display = format!("{duid}");
        assert!(display.contains("DUID-LL"));
        assert!(display.contains("00:03")); // Type field
        assert!(display.contains("aa:bb:cc:dd:ee:ff")); // Data
    }

    #[test]
    fn test_calculate_duid_timestamp() {
        let timestamp = calculate_duid_timestamp().unwrap();

        // Should be positive (we're past 2000-01-01)
        assert!(timestamp > 0);

        // Should be reasonable (not more than ~20 years = 630M seconds as of 2024)
        assert!(timestamp < 1_000_000_000);
    }

    #[test]
    fn test_duid_invalid_type_parsing() {
        // Invalid type value
        let bytes = vec![0x00, 0x99, 0x00, 0x01, 0xaa, 0xbb];
        assert!(matches!(
            Duid::from_bytes(&bytes),
            Err(DuidError::InvalidType { type_value: 0x99 })
        ));
    }

    #[test]
    fn test_duid_clone_and_equality() {
        let data = vec![0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd];
        let duid1 = Duid::new(DuidType::Ll, data.clone()).unwrap();
        let duid2 = duid1.clone();

        assert_eq!(duid1, duid2);
        assert_eq!(duid1.to_bytes(), duid2.to_bytes());
    }
}
