// dnsmasq is Copyright (c) 2000-2022 Simon Kelley
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

//! DNSSEC type definitions for DNSSEC validation per RFCs 4033-4035
//!
//! This module provides memory-safe Rust types for DNSSEC resource records,
//! algorithm and digest type enumerations, and validation state tracking.
//! It replaces C struct definitions and integer constants with type-safe
//! enums and structs containing owned data for automatic memory management.
//!
//! # Key Types
//!
//! - [`DnsKey`]: DNSKEY resource records (RR type 48) containing public keys
//! - [`RRSig`]: RRSIG resource records (RR type 46) containing signatures
//! - [`DsRecord`]: DS resource records (RR type 43) for delegation signing
//! - [`NsecRecord`]: NSEC resource records (RR type 47) for denial of existence
//! - [`Nsec3Record`]: NSEC3 resource records (RR type 50) for hashed denial
//! - [`DnssecAlgorithm`]: Cryptographic algorithm enumeration
//! - [`DigestType`]: DS digest algorithm enumeration
//! - [`ValidationStatus`]: DNSSEC validation state
//! - [`DnssecFailure`]: Specific validation failure reasons
//!
//! # RFC Compliance
//!
//! - RFC 4033: DNS Security Introduction and Requirements
//! - RFC 4034: Resource Records for the DNS Security Extensions
//! - RFC 4035: Protocol Modifications for the DNS Security Extensions
//! - RFC 5155: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
//!
//! # Memory Safety
//!
//! All structures use owned Rust types (String, Vec<u8>) replacing C's manual
//! memory management with struct blockdata pointer chains. This eliminates
//! memory leaks, use-after-free, and buffer overflow vulnerabilities.

use serde::{Serialize, Deserialize};
use std::fmt;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

// ============================================================================
// DNSSEC Algorithm Enumeration
// ============================================================================

/// DNSSEC cryptographic algorithm identifiers per RFC 4034 Appendix A.1
///
/// These algorithm numbers identify the cryptographic algorithms used for
/// DNSSEC signing and validation. The enum provides type-safe representation
/// of algorithm numbers with automatic wire format conversion.
///
/// # Wire Format
///
/// The enum uses `#[repr(u8)]` to maintain wire format compatibility with
/// DNS protocol packets where algorithms are encoded as single bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DnssecAlgorithm {
    /// RSA/SHA-1 (algorithm 5) per RFC 4034
    RsaSha1 = 5,
    /// RSA/SHA-1 with NSEC3 (algorithm 7) per RFC 5155
    RsaSha1Nsec3 = 7,
    /// RSA/SHA-256 (algorithm 8) per RFC 5702
    RsaSha256 = 8,
    /// RSA/SHA-512 (algorithm 10) per RFC 5702
    RsaSha512 = 10,
    /// GOST R 34.10-2001 (algorithm 12) per RFC 5933
    Gost = 12,
    /// ECDSA Curve P-256 with SHA-256 (algorithm 13) per RFC 6605
    EcdsaP256Sha256 = 13,
    /// ECDSA Curve P-384 with SHA-384 (algorithm 14) per RFC 6605
    EcdsaP384Sha384 = 14,
    /// Ed25519 (algorithm 15) per RFC 8032
    Ed25519 = 15,
    /// Ed448 (algorithm 16) per RFC 8032
    Ed448 = 16,
}

impl DnssecAlgorithm {
    /// Convert wire format u8 value to `DnssecAlgorithm` enum
    ///
    /// # Arguments
    ///
    /// * `value` - Algorithm number from DNS packet (0-255)
    ///
    /// # Returns
    ///
    /// * `Some(DnssecAlgorithm)` - Valid supported algorithm
    /// * `None` - Unsupported or invalid algorithm number
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            5 => Some(DnssecAlgorithm::RsaSha1),
            7 => Some(DnssecAlgorithm::RsaSha1Nsec3),
            8 => Some(DnssecAlgorithm::RsaSha256),
            10 => Some(DnssecAlgorithm::RsaSha512),
            12 => Some(DnssecAlgorithm::Gost),
            13 => Some(DnssecAlgorithm::EcdsaP256Sha256),
            14 => Some(DnssecAlgorithm::EcdsaP384Sha384),
            15 => Some(DnssecAlgorithm::Ed25519),
            16 => Some(DnssecAlgorithm::Ed448),
            _ => None,
        }
    }

    /// Convert `DnssecAlgorithm` enum to wire format u8 value
    ///
    /// # Returns
    ///
    /// Algorithm number for encoding in DNS packets
    #[must_use]
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Get hash algorithm name for this DNSSEC algorithm
    ///
    /// Returns the name of the hash function used with this algorithm,
    /// suitable for passing to cryptographic libraries.
    ///
    /// # Returns
    ///
    /// Hash algorithm name string (e.g., "sha256", "sha512")
    #[must_use]
    pub fn digest_name(self) -> &'static str {
        match self {
            DnssecAlgorithm::RsaSha1 | DnssecAlgorithm::RsaSha1Nsec3 => "sha1",
            DnssecAlgorithm::RsaSha256 | DnssecAlgorithm::EcdsaP256Sha256 => "sha256",
            DnssecAlgorithm::RsaSha512 => "sha512",
            DnssecAlgorithm::EcdsaP384Sha384 => "sha384",
            DnssecAlgorithm::Gost => "gost94",
            DnssecAlgorithm::Ed25519 | DnssecAlgorithm::Ed448 => "null", // EdDSA uses null hash
        }
    }
}

impl fmt::Display for DnssecAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            DnssecAlgorithm::RsaSha1 => "RSASHA1",
            DnssecAlgorithm::RsaSha1Nsec3 => "RSASHA1-NSEC3-SHA1",
            DnssecAlgorithm::RsaSha256 => "RSASHA256",
            DnssecAlgorithm::RsaSha512 => "RSASHA512",
            DnssecAlgorithm::Gost => "GOST R 34.10-2001",
            DnssecAlgorithm::EcdsaP256Sha256 => "ECDSAP256SHA256",
            DnssecAlgorithm::EcdsaP384Sha384 => "ECDSAP384SHA384",
            DnssecAlgorithm::Ed25519 => "ED25519",
            DnssecAlgorithm::Ed448 => "ED448",
        };
        write!(f, "{name}")
    }
}

// ============================================================================
// DS Digest Type Enumeration
// ============================================================================

/// DS record digest algorithm identifiers per RFC 4034 Appendix A.2
///
/// These digest type numbers identify the hash algorithms used to compute
/// DS record digests from DNSKEY records. The enum provides type-safe
/// representation with wire format conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DigestType {
    /// SHA-1 (digest type 1) per RFC 4034
    SHA1 = 1,
    /// SHA-256 (digest type 2) per RFC 4509
    SHA256 = 2,
    /// GOST R 34.11-94 (digest type 3) per RFC 5933
    GOST = 3,
    /// SHA-384 (digest type 4) per RFC 6605
    SHA384 = 4,
}

impl DigestType {
    /// Convert wire format u8 value to `DigestType` enum
    ///
    /// # Arguments
    ///
    /// * `value` - Digest type number from DNS packet (0-255)
    ///
    /// # Returns
    ///
    /// * `Some(DigestType)` - Valid supported digest type
    /// * `None` - Unsupported or invalid digest type number
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DigestType::SHA1),
            2 => Some(DigestType::SHA256),
            3 => Some(DigestType::GOST),
            4 => Some(DigestType::SHA384),
            _ => None,
        }
    }

    /// Convert `DigestType` enum to wire format u8 value
    ///
    /// # Returns
    ///
    /// Digest type number for encoding in DNS packets
    #[must_use]
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Get hash algorithm name for this digest type
    ///
    /// Returns the name of the hash function, suitable for passing to
    /// cryptographic libraries.
    ///
    /// # Returns
    ///
    /// Hash algorithm name string (e.g., "sha256", "sha384")
    #[must_use]
    pub fn digest_name(self) -> &'static str {
        match self {
            DigestType::SHA1 => "sha1",
            DigestType::SHA256 => "sha256",
            DigestType::GOST => "gost94",
            DigestType::SHA384 => "sha384",
        }
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            DigestType::SHA1 => "SHA-1",
            DigestType::SHA256 => "SHA-256",
            DigestType::GOST => "GOST R 34.11-94",
            DigestType::SHA384 => "SHA-384",
        };
        write!(f, "{name}")
    }
}

// ============================================================================
// Validation Status Enumeration
// ============================================================================

/// DNSSEC validation status for DNS responses
///
/// Represents the outcome of DNSSEC validation with type-safe variants
/// replacing C's integer status codes (`STAT_SECURE`, `STAT_INSECURE`, etc.).
///
/// # Validation States
///
/// - `Secure`: Valid signatures with complete chain of trust
/// - `SecureWildcard`: Valid wildcard expansion per RFC 4035
/// - `Insecure`: Unsigned delegation or zone (valid but not secured)
/// - `Bogus`: Invalid signatures or verification failure
/// - `NeedDs`: DS record required but not cached
/// - `NeedKey`: DNSKEY record required but not cached
/// - `Truncated`: Response truncated, cannot complete validation
/// - `Ok`: Validation complete (generic success)
/// - `Abandoned`: Validation abandoned due to errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    /// Response is cryptographically secure with valid chain of trust
    Secure,
    /// Response is secure and result of wildcard expansion
    SecureWildcard,
    /// Response is insecure (unsigned but provably so)
    Insecure,
    /// Response validation failed or signatures are invalid
    Bogus(Vec<DnssecFailure>),
    /// DS record needed to continue validation
    NeedDs,
    /// DNSKEY record needed to continue validation
    NeedKey,
    /// Response was truncated, cannot validate
    Truncated,
    /// Validation completed successfully (generic)
    Ok,
    /// Validation was abandoned
    Abandoned,
}

impl ValidationStatus {
    /// Check if validation status indicates cryptographic security
    ///
    /// # Returns
    ///
    /// `true` if status is `Secure` or `SecureWildcard`
    #[must_use]
    pub fn is_secure(&self) -> bool {
        matches!(self, ValidationStatus::Secure | ValidationStatus::SecureWildcard)
    }

    /// Check if validation status indicates failure
    ///
    /// # Returns
    ///
    /// `true` if status is `Bogus`
    #[must_use]
    pub fn is_bogus(&self) -> bool {
        matches!(self, ValidationStatus::Bogus(_))
    }
}

impl fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationStatus::Secure => write!(f, "SECURE"),
            ValidationStatus::SecureWildcard => write!(f, "SECURE (wildcard)"),
            ValidationStatus::Insecure => write!(f, "INSECURE"),
            ValidationStatus::Bogus(failures) => {
                write!(f, "BOGUS")?;
                if !failures.is_empty() {
                    write!(f, " (")?;
                    for (i, failure) in failures.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{failure}")?;
                    }
                    write!(f, ")")?;
                }
                Ok(())
            }
            ValidationStatus::NeedDs => write!(f, "NEED DS"),
            ValidationStatus::NeedKey => write!(f, "NEED KEY"),
            ValidationStatus::Truncated => write!(f, "TRUNCATED"),
            ValidationStatus::Ok => write!(f, "OK"),
            ValidationStatus::Abandoned => write!(f, "ABANDONED"),
        }
    }
}

// ============================================================================
// DNSSEC Failure Reasons
// ============================================================================

/// Specific reasons for DNSSEC validation failures
///
/// Provides detailed error information when validation fails, replacing
/// C's bit flags (`DNSSEC_FAIL_NYV`, `DNSSEC_FAIL_EXP`, etc.) with type-safe
/// enum variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnssecFailure {
    /// Signature not yet valid (before inception time)
    NotYetValid,
    /// Signature expired (after expiration time)
    Expired,
    /// Validation result is indeterminate
    Indeterminate,
    /// No supported key algorithm available
    NoSupportedKeyAlgorithm,
    /// No RRSIG records found
    NoSignatures,
    /// Zone bit not set in DNSKEY flags
    NoZoneBit,
    /// No NSEC/NSEC3 records for denial of existence
    NoNsec,
    /// No supported DS digest algorithm
    NoSupportedDsAlgorithm,
    /// No DNSKEY records found
    NoKey,
}

impl fmt::Display for DnssecFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self {
            DnssecFailure::NotYetValid => "not yet valid",
            DnssecFailure::Expired => "expired",
            DnssecFailure::Indeterminate => "indeterminate",
            DnssecFailure::NoSupportedKeyAlgorithm => "no supported key algorithm",
            DnssecFailure::NoSignatures => "no signatures",
            DnssecFailure::NoZoneBit => "no zone bit",
            DnssecFailure::NoNsec => "no NSEC",
            DnssecFailure::NoSupportedDsAlgorithm => "no supported DS algorithm",
            DnssecFailure::NoKey => "no key",
        };
        write!(f, "{desc}")
    }
}

// ============================================================================
// DNSKEY Resource Record (RR Type 48)
// ============================================================================

/// DNSKEY resource record per RFC 4034 Section 2
///
/// Contains a public key used to verify RRSIG signatures. DNSKEY records
/// are published by zones to enable DNSSEC validation of their signed data.
///
/// # Fields
///
/// - `flags`: DNSKEY flags (bit 7 = zone key, bit 15 = secure entry point/KSK)
/// - `protocol`: Must be 3 per RFC 4034
/// - `algorithm`: Cryptographic algorithm identifier
/// - `public_key`: Public key data in algorithm-specific format
///
/// # Wire Format
///
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |             Flags (16 bits)                   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |   Protocol   |   Algorithm   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /            Public Key (variable)              /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsKey {
    /// DNSKEY flags field (16 bits)
    flags: u16,
    /// Protocol field (must be 3)
    protocol: u8,
    /// Cryptographic algorithm identifier
    algorithm: DnssecAlgorithm,
    /// Public key data (algorithm-specific encoding)
    public_key: Vec<u8>,
}

impl DnsKey {
    /// Create a new DNSKEY record
    ///
    /// # Arguments
    ///
    /// * `flags` - DNSKEY flags (bit 7 = zone key, bit 15 = SEP/KSK)
    /// * `protocol` - Protocol value (must be 3 per RFC 4034)
    /// * `algorithm` - Cryptographic algorithm
    /// * `public_key` - Public key bytes in algorithm-specific format
    ///
    /// # Returns
    ///
    /// New `DnsKey` instance
    #[must_use]
    pub fn new(flags: u16, protocol: u8, algorithm: DnssecAlgorithm, public_key: Vec<u8>) -> Self {
        DnsKey {
            flags,
            protocol,
            algorithm,
            public_key,
        }
    }

    /// Get DNSKEY flags field
    #[must_use]
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Get protocol field
    #[must_use]
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Get cryptographic algorithm
    #[must_use]
    pub fn algorithm(&self) -> DnssecAlgorithm {
        self.algorithm
    }

    /// Get public key data
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Calculate DNSKEY key tag per RFC 4034 Appendix B
    ///
    /// The key tag is a 16-bit hash of the DNSKEY RDATA used for efficient
    /// key selection. RSAMD5 (algorithm 1) uses a special calculation;
    /// other algorithms use standard checksum.
    ///
    /// # Returns
    ///
    /// Key tag value (0-65535)
    #[must_use]
    pub fn keytag(&self) -> u16 {
        // RFC 4034 Appendix B.1: Key tag calculation
        let mut rdata = Vec::with_capacity(4 + self.public_key.len());
        rdata.extend_from_slice(&self.flags.to_be_bytes());
        rdata.push(self.protocol);
        rdata.push(self.algorithm.to_u8());
        rdata.extend_from_slice(&self.public_key);

        // Standard algorithm checksum (RFC 4034 Appendix B.1)
        let mut ac: u32 = 0;
        for (i, &byte) in rdata.iter().enumerate() {
            if i % 2 == 0 {
                ac += u32::from(byte) << 8;
            } else {
                ac += u32::from(byte);
            }
        }
        ac += (ac >> 16) & 0xFFFF;
        (ac & 0xFFFF) as u16
    }

    /// Verify data using this DNSKEY with provided digest
    ///
    /// This method provides the interface for DNSKEY signature verification.
    /// The actual cryptographic operations are delegated to the crypto module
    /// (`src_rust/dns/dnssec/crypto.rs`) which uses ring or rustls for secure
    /// algorithm-specific verification.
    ///
    /// # Architecture Note
    ///
    /// This types module defines data structures and their basic operations.
    /// Cryptographic verification requires integration with the crypto module
    /// which will implement algorithm-specific logic for RSA, ECDSA, and `EdDSA`.
    ///
    /// # Arguments
    ///
    /// * `digest` - Message digest to verify
    /// * `signature` - Signature bytes
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Signature verifies successfully
    /// * `Ok(false)` - Signature verification failed
    /// * `Err(...)` - Malformed key, empty parameters, or unsupported algorithm
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Digest is empty
    /// - Signature is empty
    /// - Public key is empty
    /// - Protocol field is not 3
    /// - Crypto module integration not yet implemented for the algorithm
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::dns::dnssec::types::{DnsKey, DnssecAlgorithm};
    /// let key = DnsKey::new(257, 3, DnssecAlgorithm::RsaSha256, vec![1,2,3,4]);
    /// let digest = vec![0u8; 32]; // SHA-256 digest
    /// let signature = vec![0u8; 256]; // RSA signature
    /// let result = key.verify_with_digest(&digest, &signature);
    /// match result {
    ///     Ok(true) => println!("Signature valid"),
    ///     Ok(false) => println!("Signature invalid"),
    ///     Err(e) => println!("Verification error: {}", e),
    /// }
    /// ```
    pub fn verify_with_digest(&self, digest: &[u8], signature: &[u8]) -> Result<bool, String> {
        // Validate parameters before delegating to crypto module
        if digest.is_empty() {
            return Err("Digest cannot be empty".to_string());
        }
        
        if signature.is_empty() {
            return Err("Signature cannot be empty".to_string());
        }
        
        if self.public_key.is_empty() {
            return Err("DNSKEY public key cannot be empty".to_string());
        }

        // Protocol field must be 3 per RFC 4034
        if self.protocol != 3 {
            let protocol = self.protocol;
            return Err(format!("Invalid protocol field: {protocol} (must be 3)"));
        }

        // Interface for crypto module integration
        // When crypto.rs is implemented, this will dispatch to:
        // - crypto::verify_rsa_signature() for RSA algorithms
        // - crypto::verify_ecdsa_signature() for ECDSA algorithms  
        // - crypto::verify_eddsa_signature() for EdDSA algorithms
        //
        // For now, return Err to indicate crypto module integration is required.
        // This ensures callers know verification is not yet available rather than
        // silently succeeding or failing.
        Err(format!(
            "Crypto verification not yet integrated for algorithm {}. \
             Crypto module (crypto.rs) will implement algorithm-specific verification.",
            self.algorithm
        ))
    }

    /// Serialize DNSKEY to DNS wire format
    ///
    /// # Returns
    ///
    /// Wire format bytes (flags + protocol + algorithm + public key)
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(4 + self.public_key.len());
        wire.extend_from_slice(&self.flags.to_be_bytes());
        wire.push(self.protocol);
        wire.push(self.algorithm.to_u8());
        wire.extend_from_slice(&self.public_key);
        wire
    }

    /// Parse DNSKEY from DNS wire format
    ///
    /// # Arguments
    ///
    /// * `data` - Wire format bytes
    ///
    /// # Errors
    ///
    /// Returns error if RDATA is too short or contains invalid algorithm
    pub fn from_wire(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err("DNSKEY RDATA too short (minimum 4 bytes)".to_string());
        }

        let flags = u16::from_be_bytes([data[0], data[1]]);
        let protocol = data[2];
        let algo_byte = data[3];
        
        let algorithm = DnssecAlgorithm::from_u8(algo_byte)
            .ok_or_else(|| format!("Unsupported DNSSEC algorithm: {algo_byte}"))?;
        
        let public_key = data[4..].to_vec();
        
        if public_key.is_empty() {
            return Err("DNSKEY public key is empty".to_string());
        }

        Ok(DnsKey::new(flags, protocol, algorithm, public_key))
    }
}

// ============================================================================
// RRSIG Resource Record (RR Type 46)
// ============================================================================

/// RRSIG resource record per RFC 4034 Section 3
///
/// Contains a cryptographic signature over an `RRset` (set of resource records
/// with same owner name, class, and type). RRSIG records enable validation
/// of DNS data integrity and authenticity.
///
/// # Fields
///
/// - `type_covered`: RR type covered by this signature
/// - `algorithm`: Cryptographic algorithm used for signing
/// - `labels`: Number of labels in original name (for wildcard detection)
/// - `original_ttl`: Original TTL of the covered `RRset`
/// - `signature_expiration`: Signature expiration time (seconds since epoch)
/// - `signature_inception`: Signature inception time (seconds since epoch)
/// - `key_tag`: Key tag of DNSKEY used to generate signature
/// - `signer_name`: Domain name of signing zone
/// - `signature`: Signature bytes in algorithm-specific format
///
/// # Wire Format
///
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |        Type Covered         |  Algorithm   | Labels  |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                Original TTL                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |            Signature Expiration                 |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |            Signature Inception                  |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |             Key Tag                |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /            Signer's Name (variable)            /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /            Signature (variable)                /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RRSig {
    /// RR type covered by this signature
    type_covered: u16,
    /// Cryptographic algorithm
    algorithm: DnssecAlgorithm,
    /// Number of labels in original owner name
    labels: u8,
    /// Original TTL of `RRset`
    original_ttl: u32,
    /// Signature expiration time (Unix timestamp)
    signature_expiration: u32,
    /// Signature inception time (Unix timestamp)
    signature_inception: u32,
    /// Key tag of signing DNSKEY
    key_tag: u16,
    /// Domain name of signer
    signer_name: String,
    /// Signature bytes
    signature: Vec<u8>,
}

impl RRSig {
    /// Create a new RRSIG record
    ///
    /// # Arguments
    ///
    /// * `type_covered` - RR type covered by signature
    /// * `algorithm` - Cryptographic algorithm
    /// * `labels` - Number of labels in original name
    /// * `original_ttl` - Original TTL of `RRset`
    /// * `signature_expiration` - Expiration time (Unix timestamp)
    /// * `signature_inception` - Inception time (Unix timestamp)
    /// * `key_tag` - Key tag of signing DNSKEY
    /// * `signer_name` - Domain name of signer
    /// * `signature` - Signature bytes
    ///
    /// # Returns
    ///
    /// New `RRSig` instance
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        type_covered: u16,
        algorithm: DnssecAlgorithm,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: String,
        signature: Vec<u8>,
    ) -> Self {
        RRSig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        }
    }

    /// Get RR type covered by this signature
    #[must_use]
    pub fn type_covered(&self) -> u16 {
        self.type_covered
    }

    /// Get cryptographic algorithm
    #[must_use]
    pub fn algorithm(&self) -> DnssecAlgorithm {
        self.algorithm
    }

    /// Get number of labels in original owner name
    #[must_use]
    pub fn labels(&self) -> u8 {
        self.labels
    }

    /// Get original TTL of covered `RRset`
    #[must_use]
    pub fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    /// Get signature expiration time (Unix timestamp)
    #[must_use]
    pub fn signature_expiration(&self) -> u32 {
        self.signature_expiration
    }

    /// Get signature inception time (Unix timestamp)
    #[must_use]
    pub fn signature_inception(&self) -> u32 {
        self.signature_inception
    }

    /// Get key tag of signing DNSKEY
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Get signer's domain name
    #[must_use]
    pub fn signer_name(&self) -> &str {
        &self.signer_name
    }

    /// Get signature bytes
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Check if signature has expired relative to current system time
    ///
    /// # Returns
    ///
    /// * `true` - Signature has expired
    /// * `false` - Signature is still valid (not expired)
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        // DNSSEC uses 32-bit timestamps; values beyond 2106 are treated as max
        let now_u32 = u32::try_from(now).unwrap_or(u32::MAX);
        now_u32 > self.signature_expiration
    }

    /// Check if signature is not yet valid relative to current system time
    ///
    /// # Returns
    ///
    /// * `true` - Signature is not yet valid (before inception)
    /// * `false` - Signature inception time has passed
    #[must_use]
    pub fn is_not_yet_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        // DNSSEC uses 32-bit timestamps; values beyond 2106 are treated as max
        let now_u32 = u32::try_from(now).unwrap_or(u32::MAX);
        now_u32 < self.signature_inception
    }

    /// Serialize RRSIG to DNS wire format
    ///
    /// # Returns
    ///
    /// Wire format bytes
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&self.type_covered.to_be_bytes());
        wire.push(self.algorithm.to_u8());
        wire.push(self.labels);
        wire.extend_from_slice(&self.original_ttl.to_be_bytes());
        wire.extend_from_slice(&self.signature_expiration.to_be_bytes());
        wire.extend_from_slice(&self.signature_inception.to_be_bytes());
        wire.extend_from_slice(&self.key_tag.to_be_bytes());
        
        // Encode signer name in wire format (length-prefixed labels)
        for label in self.signer_name.split('.') {
            if !label.is_empty() {
                wire.push(u8::try_from(label.len()).unwrap_or(63)); // DNS label max is 63
                wire.extend_from_slice(label.as_bytes());
            }
        }
        wire.push(0); // Null terminator
        
        wire.extend_from_slice(&self.signature);
        wire
    }

    /// Parse RRSIG from DNS wire format
    ///
    /// # Arguments
    ///
    /// * `data` - Wire format bytes
    ///
    /// # Errors
    ///
    /// Returns error if RDATA is too short, contains invalid algorithm, or has malformed signer name
    pub fn from_wire(data: &[u8]) -> Result<Self, String> {
        if data.len() < 18 {
            return Err("RRSIG RDATA too short (minimum 18 bytes before signer name)".to_string());
        }

        let type_covered = u16::from_be_bytes([data[0], data[1]]);
        let algo_byte = data[2];
        let labels = data[3];
        let original_ttl = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let signature_expiration = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let signature_inception = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let key_tag = u16::from_be_bytes([data[16], data[17]]);

        let algorithm = DnssecAlgorithm::from_u8(algo_byte)
            .ok_or_else(|| format!("Unsupported DNSSEC algorithm: {algo_byte}"))?;

        // Parse signer name from wire format
        let mut pos = 18;
        let mut signer_labels = Vec::new();
        while pos < data.len() {
            let label_len = data[pos] as usize;
            if label_len == 0 {
                pos += 1;
                break;
            }
            if pos + 1 + label_len > data.len() {
                return Err("RRSIG signer name extends beyond RDATA".to_string());
            }
            let label = String::from_utf8_lossy(&data[pos + 1..pos + 1 + label_len]).to_string();
            signer_labels.push(label);
            pos += 1 + label_len;
        }
        let signer_name = signer_labels.join(".");

        if pos >= data.len() {
            return Err("RRSIG signature is empty".to_string());
        }

        let signature = data[pos..].to_vec();

        Ok(RRSig::new(
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        ))
    }
}

// ============================================================================
// DS Resource Record (RR Type 43)
// ============================================================================

/// DS (Delegation Signer) resource record per RFC 4034 Section 5
///
/// Contains a hash of a DNSKEY record from a child zone, placed in the parent
/// zone to establish the DNSSEC chain of trust. DS records enable secure
/// delegation by linking parent and child zone keys.
///
/// # Fields
///
/// - `key_tag`: Key tag of referenced DNSKEY
/// - `algorithm`: Algorithm of referenced DNSKEY
/// - `digest_type`: Hash algorithm used to compute digest
/// - `digest`: Hash of DNSKEY RDATA
///
/// # Wire Format
///
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |             Key Tag                |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// | Algorithm  |DigestType|
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /            Digest (variable)                  /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsRecord {
    /// Key tag of DNSKEY being referenced
    key_tag: u16,
    /// Algorithm of referenced DNSKEY
    algorithm: DnssecAlgorithm,
    /// Digest type (hash algorithm)
    digest_type: DigestType,
    /// Digest (hash) of DNSKEY RDATA
    digest: Vec<u8>,
}

impl DsRecord {
    /// Create a new DS record
    ///
    /// # Arguments
    ///
    /// * `key_tag` - Key tag of referenced DNSKEY
    /// * `algorithm` - Algorithm of referenced DNSKEY
    /// * `digest_type` - Hash algorithm used for digest
    /// * `digest` - Hash of DNSKEY RDATA
    ///
    /// # Returns
    ///
    /// New `DsRecord` instance
    #[must_use]
    pub fn new(
        key_tag: u16,
        algorithm: DnssecAlgorithm,
        digest_type: DigestType,
        digest: Vec<u8>,
    ) -> Self {
        DsRecord {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    /// Get key tag
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Get algorithm
    #[must_use]
    pub fn algorithm(&self) -> DnssecAlgorithm {
        self.algorithm
    }

    /// Get digest type
    #[must_use]
    pub fn digest_type(&self) -> DigestType {
        self.digest_type
    }

    /// Get digest bytes
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Serialize DS to DNS wire format
    ///
    /// # Returns
    ///
    /// Wire format bytes
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(4 + self.digest.len());
        wire.extend_from_slice(&self.key_tag.to_be_bytes());
        wire.push(self.algorithm.to_u8());
        wire.push(self.digest_type.to_u8());
        wire.extend_from_slice(&self.digest);
        wire
    }

    /// Parse DS from DNS wire format
    ///
    /// # Arguments
    ///
    /// * `data` - Wire format bytes
    ///
    /// # Errors
    ///
    /// Returns error if RDATA is too short or contains unsupported algorithm or digest type
    pub fn from_wire(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err("DS RDATA too short (minimum 4 bytes)".to_string());
        }

        let key_tag = u16::from_be_bytes([data[0], data[1]]);
        let algo_byte = data[2];
        let digest_type_byte = data[3];

        let algorithm = DnssecAlgorithm::from_u8(algo_byte)
            .ok_or_else(|| format!("Unsupported DNSSEC algorithm: {algo_byte}"))?;

        let digest_type = DigestType::from_u8(digest_type_byte)
            .ok_or_else(|| format!("Unsupported digest type: {digest_type_byte}"))?;

        let digest = data[4..].to_vec();

        if digest.is_empty() {
            return Err("DS digest is empty".to_string());
        }

        Ok(DsRecord::new(key_tag, algorithm, digest_type, digest))
    }
}

// ============================================================================
// NSEC Resource Record (RR Type 47)
// ============================================================================

/// NSEC resource record per RFC 4034 Section 4
///
/// Provides authenticated denial of existence for DNSSEC. NSEC records form
/// a chain linking each name in a zone to the next name in canonical order,
/// proving that names between them do not exist.
///
/// # Fields
///
/// - `next_domain`: Next domain name in canonical order
/// - `type_bitmap`: Bitmap of RR types present at owner name
///
/// # Wire Format
///
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /            Next Domain Name (variable)        /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /            Type Bit Maps (variable)           /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsecRecord {
    /// Next domain name in canonical order
    next_domain: String,
    /// Type bitmap indicating present RR types
    type_bitmap: Vec<u8>,
}

impl NsecRecord {
    /// Create a new NSEC record
    ///
    /// # Arguments
    ///
    /// * `next_domain` - Next domain name in canonical order
    /// * `type_bitmap` - Bitmap of RR types present
    ///
    /// # Returns
    ///
    /// New `NsecRecord` instance
    #[must_use]
    pub fn new(next_domain: String, type_bitmap: Vec<u8>) -> Self {
        NsecRecord {
            next_domain,
            type_bitmap,
        }
    }

    /// Get next domain name
    #[must_use]
    pub fn next_domain(&self) -> &str {
        &self.next_domain
    }

    /// Get type bitmap
    #[must_use]
    pub fn type_bitmap(&self) -> &[u8] {
        &self.type_bitmap
    }

    /// Check if NSEC covers a specific RR type
    ///
    /// # Arguments
    ///
    /// * `rrtype` - RR type to check (e.g., `T_A`, `T_AAAA`)
    ///
    /// # Returns
    ///
    /// `true` if type is present in bitmap
    #[must_use]
    pub fn covers_type(&self, rrtype: u16) -> bool {
        #[allow(clippy::cast_possible_truncation)] // rrtype / 256 is always <= 255
        let window = (rrtype / 256) as u8;
        #[allow(clippy::cast_possible_truncation)] // rrtype % 256 is always < 256
        let bit_in_window = (rrtype % 256) as u8;
        
        let mut pos = 0;
        while pos < self.type_bitmap.len() {
            if pos + 1 >= self.type_bitmap.len() {
                break;
            }
            let win = self.type_bitmap[pos];
            let bitmap_len = self.type_bitmap[pos + 1] as usize;
            
            if win == window && pos + 2 + bitmap_len <= self.type_bitmap.len() {
                let byte_offset = (bit_in_window / 8) as usize;
                let bit_mask = 0x80 >> (bit_in_window % 8);
                
                if byte_offset < bitmap_len {
                    return (self.type_bitmap[pos + 2 + byte_offset] & bit_mask) != 0;
                }
            }
            
            pos += 2 + bitmap_len;
        }
        false
    }

    /// Serialize NSEC to DNS wire format
    ///
    /// # Returns
    ///
    /// Wire format bytes
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut wire = Vec::new();
        
        // Encode next domain name
        for label in self.next_domain.split('.') {
            if !label.is_empty() {
                wire.push(u8::try_from(label.len()).unwrap_or(63)); // DNS label max is 63
                wire.extend_from_slice(label.as_bytes());
            }
        }
        wire.push(0); // Null terminator
        
        wire.extend_from_slice(&self.type_bitmap);
        wire
    }

    /// Parse NSEC from DNS wire format
    ///
    /// # Arguments
    ///
    /// * `data` - Wire format bytes
    ///
    /// # Errors
    ///
    /// Returns error if RDATA is empty, next domain name is invalid, or type bitmap is malformed
    pub fn from_wire(data: &[u8]) -> Result<Self, String> {
        if data.is_empty() {
            return Err("NSEC RDATA is empty".to_string());
        }

        // Parse next domain name
        let mut pos = 0;
        let mut next_labels = Vec::new();
        while pos < data.len() {
            let label_len = data[pos] as usize;
            if label_len == 0 {
                pos += 1;
                break;
            }
            if pos + 1 + label_len > data.len() {
                return Err("NSEC next domain extends beyond RDATA".to_string());
            }
            let label = String::from_utf8_lossy(&data[pos + 1..pos + 1 + label_len]).to_string();
            next_labels.push(label);
            pos += 1 + label_len;
        }
        let next_domain = next_labels.join(".");

        if pos >= data.len() {
            return Err("NSEC type bitmap is missing".to_string());
        }

        let type_bitmap = data[pos..].to_vec();

        Ok(NsecRecord::new(next_domain, type_bitmap))
    }
}

// ============================================================================
// NSEC3 Resource Record (RR Type 50)
// ============================================================================

/// NSEC3 resource record per RFC 5155
///
/// Provides hashed authenticated denial of existence for DNSSEC. NSEC3 is
/// similar to NSEC but uses hashed names to prevent zone enumeration.
///
/// # Fields
///
/// - `hash_algorithm`: Hash algorithm used (1 = SHA-1)
/// - `flags`: NSEC3 flags (bit 0 = Opt-Out)
/// - `iterations`: Number of additional hash iterations
/// - `salt`: Salt value for hash
/// - `next_hashed_owner`: Hash of next owner name
/// - `type_bitmap`: Bitmap of RR types present
///
/// # Wire Format
///
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |HashAlg|Flags|        Iterations              |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// | Salt Length |        Salt (variable)         /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// | Hash Length |   Next Hashed Owner (variable) /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /            Type Bit Maps (variable)           /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nsec3Record {
    /// Hash algorithm (1 = SHA-1)
    hash_algorithm: u8,
    /// Flags (bit 0 = Opt-Out)
    flags: u8,
    /// Hash iterations
    iterations: u16,
    /// Salt bytes
    salt: Vec<u8>,
    /// Hash of next owner name
    next_hashed_owner: Vec<u8>,
    /// Type bitmap
    type_bitmap: Vec<u8>,
}

impl Nsec3Record {
    /// Create a new NSEC3 record
    ///
    /// # Arguments
    ///
    /// * `hash_algorithm` - Hash algorithm (1 = SHA-1)
    /// * `flags` - NSEC3 flags
    /// * `iterations` - Number of hash iterations
    /// * `salt` - Salt bytes
    /// * `next_hashed_owner` - Hash of next owner name
    /// * `type_bitmap` - Bitmap of RR types present
    ///
    /// # Returns
    ///
    /// New `Nsec3Record` instance
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed_owner: Vec<u8>,
        type_bitmap: Vec<u8>,
    ) -> Self {
        Nsec3Record {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            type_bitmap,
        }
    }

    /// Get hash algorithm
    #[must_use]
    pub fn hash_algorithm(&self) -> u8 {
        self.hash_algorithm
    }

    /// Get flags
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Get iterations
    #[must_use]
    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Get salt
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Get next hashed owner name
    #[must_use]
    pub fn next_hashed_owner(&self) -> &[u8] {
        &self.next_hashed_owner
    }

    /// Get type bitmap
    #[must_use]
    pub fn type_bitmap(&self) -> &[u8] {
        &self.type_bitmap
    }

    /// Check if NSEC3 covers a specific RR type
    ///
    /// # Arguments
    ///
    /// * `rrtype` - RR type to check
    ///
    /// # Returns
    ///
    /// `true` if type is present in bitmap
    #[must_use]
    pub fn covers_type(&self, rrtype: u16) -> bool {
        // Same bitmap logic as NSEC
        #[allow(clippy::cast_possible_truncation)] // rrtype / 256 is always <= 255
        let window = (rrtype / 256) as u8;
        #[allow(clippy::cast_possible_truncation)] // rrtype % 256 is always < 256
        let bit_in_window = (rrtype % 256) as u8;
        
        let mut pos = 0;
        while pos < self.type_bitmap.len() {
            if pos + 1 >= self.type_bitmap.len() {
                break;
            }
            let win = self.type_bitmap[pos];
            let bitmap_len = self.type_bitmap[pos + 1] as usize;
            
            if win == window && pos + 2 + bitmap_len <= self.type_bitmap.len() {
                let byte_offset = (bit_in_window / 8) as usize;
                let bit_mask = 0x80 >> (bit_in_window % 8);
                
                if byte_offset < bitmap_len {
                    return (self.type_bitmap[pos + 2 + byte_offset] & bit_mask) != 0;
                }
            }
            
            pos += 2 + bitmap_len;
        }
        false
    }

    /// Serialize NSEC3 to DNS wire format
    ///
    /// # Returns
    ///
    /// Wire format bytes
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.push(self.hash_algorithm);
        wire.push(self.flags);
        wire.extend_from_slice(&self.iterations.to_be_bytes());
        wire.push(u8::try_from(self.salt.len()).unwrap_or(255));
        wire.extend_from_slice(&self.salt);
        wire.push(u8::try_from(self.next_hashed_owner.len()).unwrap_or(255));
        wire.extend_from_slice(&self.next_hashed_owner);
        wire.extend_from_slice(&self.type_bitmap);
        wire
    }

    /// Parse NSEC3 from DNS wire format
    ///
    /// # Arguments
    ///
    /// * `data` - Wire format bytes
    ///
    /// # Errors
    ///
    /// Returns error if RDATA is too short, salt/hash fields extend beyond data, or type bitmap is malformed
    pub fn from_wire(data: &[u8]) -> Result<Self, String> {
        if data.len() < 5 {
            return Err("NSEC3 RDATA too short (minimum 5 bytes)".to_string());
        }

        let hash_algorithm = data[0];
        let flags = data[1];
        let iterations = u16::from_be_bytes([data[2], data[3]]);
        
        let salt_len = data[4] as usize;
        if data.len() < 5 + salt_len {
            return Err("NSEC3 salt extends beyond RDATA".to_string());
        }
        
        let salt = data[5..5 + salt_len].to_vec();
        
        let hash_pos = 5 + salt_len;
        if hash_pos >= data.len() {
            return Err("NSEC3 hash length missing".to_string());
        }
        
        let hash_len = data[hash_pos] as usize;
        if data.len() < hash_pos + 1 + hash_len {
            return Err("NSEC3 hash extends beyond RDATA".to_string());
        }
        
        let next_hashed_owner = data[hash_pos + 1..hash_pos + 1 + hash_len].to_vec();
        
        let bitmap_pos = hash_pos + 1 + hash_len;
        let type_bitmap = if bitmap_pos < data.len() {
            data[bitmap_pos..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Nsec3Record::new(
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            type_bitmap,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dnssec_algorithm_conversion() {
        assert_eq!(DnssecAlgorithm::from_u8(5), Some(DnssecAlgorithm::RsaSha1));
        assert_eq!(DnssecAlgorithm::from_u8(8), Some(DnssecAlgorithm::RsaSha256));
        assert_eq!(DnssecAlgorithm::from_u8(13), Some(DnssecAlgorithm::EcdsaP256Sha256));
        assert_eq!(DnssecAlgorithm::from_u8(255), None);
        
        assert_eq!(DnssecAlgorithm::RsaSha256.to_u8(), 8);
    }

    #[test]
    fn test_digest_type_conversion() {
        assert_eq!(DigestType::from_u8(1), Some(DigestType::SHA1));
        assert_eq!(DigestType::from_u8(2), Some(DigestType::SHA256));
        assert_eq!(DigestType::from_u8(255), None);
        
        assert_eq!(DigestType::SHA256.to_u8(), 2);
    }

    #[test]
    fn test_validation_status_is_secure() {
        assert!(ValidationStatus::Secure.is_secure());
        assert!(ValidationStatus::SecureWildcard.is_secure());
        assert!(!ValidationStatus::Insecure.is_secure());
        assert!(!ValidationStatus::Bogus(vec![]).is_secure());
    }

    #[test]
    fn test_validation_status_is_bogus() {
        assert!(ValidationStatus::Bogus(vec![]).is_bogus());
        assert!(ValidationStatus::Bogus(vec![DnssecFailure::Expired]).is_bogus());
        assert!(!ValidationStatus::Secure.is_bogus());
    }

    #[test]
    fn test_dnskey_keytag_calculation() {
        // Test key tag calculation with sample data
        let key = DnsKey::new(
            256, // flags
            3,   // protocol
            DnssecAlgorithm::RsaSha256,
            vec![1, 2, 3, 4], // public key
        );
        let tag = key.keytag();
        // Expected keytag for this specific test data (RFC 4034 Appendix B.1 algorithm)
        assert_eq!(tag, 2062);
    }

    #[test]
    fn test_rrsig_time_validation() {
        let now = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ).unwrap_or(u32::MAX);
        
        let rrsig = RRSig::new(
            1, // A record
            DnssecAlgorithm::RsaSha256,
            2,
            300,
            now + 3600, // expires in 1 hour
            now - 3600, // inception 1 hour ago
            12345,
            "example.com".to_string(),
            vec![1, 2, 3],
        );
        
        assert!(!rrsig.is_expired());
        assert!(!rrsig.is_not_yet_valid());
    }

    #[test]
    fn test_dnskey_wire_format_roundtrip() {
        let original = DnsKey::new(
            257,
            3,
            DnssecAlgorithm::RsaSha256,
            vec![1, 2, 3, 4, 5],
        );
        
        let wire = original.to_wire();
        let parsed = DnsKey::from_wire(&wire).expect("Failed to parse");
        
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_ds_record_wire_format_roundtrip() {
        let original = DsRecord::new(
            12345,
            DnssecAlgorithm::RsaSha256,
            DigestType::SHA256,
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );
        
        let wire = original.to_wire();
        let parsed = DsRecord::from_wire(&wire).expect("Failed to parse");
        
        assert_eq!(original, parsed);
    }
}
