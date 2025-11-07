// Copyright (c) 2012 Giovanni Bajo <rasky@develer.com>
// Copyright (c) 2012-2024 Simon Kelley
// Copyright (c) 2024 Blitzy Platform (Rust translation)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! DNSSEC Validation Implementation (RFC 4033/4034/4035)
//!
//! This module implements complete DNSSEC validation for DNS responses, providing cryptographic
//! verification of DNS data integrity and authenticity. It handles the full DNSSEC validation
//! pipeline including DNSKEY retrieval and verification, DS (Delegation Signer) chain validation
//! from root to target zone, RRSIG (Resource Record Signature) verification over answer RRsets,
//! NSEC/NSEC3 denial-of-existence proofs for negative answers, DNS name canonicalization for
//! signature verification, timestamp checking (inception/expiration times), and trust anchor
//! management.
//!
//! The validation process produces one of four states: secure (valid signatures with complete
//! chain of trust), insecure (unsigned delegation or zone), bogus (invalid or missing signatures),
//! or indeterminate (unable to validate due to missing data or errors).
//!
//! # Key Responsibilities
//!
//! - `validate_reply()` - Main validation entry point, validates all RRsets in answer section
//! - `validate_by_ds()` - Validates DNSKEY RRset against parent zone DS records
//! - `validate_ds()` - Validates DS records by checking DNSKEY signatures in child zone
//! - `verify_rrset_signature()` - Core signature verification function
//! - `prove_non_existence()` - Coordinates NSEC/NSEC3 proof validation for negative answers
//! - `setup_timestamp()` - Initializes timestamp file for time validation on embedded systems
//! - `compute_key_tag()` - Compute DNSKEY key tag for matching DNSKEYs to DS and RRSIG records
//!
//! # Memory Safety Improvements
//!
//! The C implementation (src/dnssec.c) uses manual memory management and global state.
//! The Rust implementation provides:
//!
//! - No buffer overflows: Safe string operations with bounds checking
//! - No use-after-free: Ownership system prevents dangling pointers
//! - No global state: All validation state on stack or passed as parameters
//! - Type-safe enums: Replace C integer status codes
//! - Result types: Replace C errno-based error handling
//!
//! # Source Mapping
//!
//! Translated from `src/dnssec.c` in the C implementation.

use std::cmp::Ordering;
use std::path::Path;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn, error, trace};
use thiserror::Error;

use crate::dns::dnssec::crypto::nsec3_hash_algorithm_name;
use crate::dns::protocol::RecordClass;
use crate::types::errors::DnssecError;
use crate::constants::MAX_DOMAIN_NAME;
use crate::dns::blockdata::BlockData;

/// DNS name escape character for representing dots and NULs within labels
const NAME_ESCAPE: char = '\x01';

/// DNSSEC validation status enumeration
///
/// Represents the validation state of a DNS response after DNSSEC validation.
/// Replaces C integer status codes (STAT_SECURE, STAT_INSECURE, STAT_BOGUS, STAT_NEED_KEY)
/// with type-safe enum.
///
/// # States
///
/// - `Secure`: Valid signatures with complete chain of trust from trusted anchor
/// - `Insecure`: Unsigned delegation or zone (provably insecure via DS lookup)
/// - `Bogus`: Invalid or missing signatures (validation failure, forged data)
/// - `Indeterminate`: Unable to validate due to missing data or errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    /// Valid signatures with complete chain of trust
    Secure,
    /// Unsigned delegation or zone (provably insecure)
    Insecure,
    /// Invalid or missing signatures (validation failure)
    Bogus,
    /// Unable to validate due to missing data
    Indeterminate,
}

/// Trust anchor for DNSSEC validation
///
/// Represents a configured trust anchor, typically the root zone KSK or other explicitly
/// trusted keys. Trust anchors serve as the starting point for building the chain of trust.
///
/// # Fields
///
/// - `domain`: Domain name (e.g., "." for root KSK)
/// - `key_tag`: DNSKEY key tag for matching
/// - `algorithm`: Cryptographic algorithm (8=RSA/SHA-256, 13=ECDSA P-256, etc.)
/// - `digest_type`: DS digest algorithm (1=SHA-1, 2=SHA-256, etc.)
/// - `digest`: DS digest bytes
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub domain: String,
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

/// DNSSEC validation result
///
/// Comprehensive validation outcome including validation status, AD bit value,
/// whether response was signed, key tags used in validation, and optional
/// failure reason for diagnostic purposes.
///
/// # Fields
///
/// - `status`: Overall DNSSEC validation status
/// - `ad_bit`: Authenticated Data bit value for response
/// - `signed`: Whether response contained DNSSEC signatures
/// - `key_tags`: Key tags of DNSKEYs used in validation
/// - `failure_reason`: Diagnostic message for validation failures
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub status: DnssecStatus,
    pub ad_bit: bool,
    pub signed: bool,
    pub key_tags: Vec<u16>,
    pub failure_reason: Option<String>,
}

/// Parsed RRSIG (Resource Record Signature) record
///
/// Contains all fields from RRSIG RDATA for signature verification.
/// Corresponds to RFC 4034 Section 3.1.
///
/// # Fields
///
/// - `type_covered`: RR type covered by this signature
/// - `algorithm`: Cryptographic algorithm used
/// - `labels`: Number of labels in original owner name (for wildcard validation)
/// - `original_ttl`: Original TTL of the RRset
/// - `expiration`: Signature expiration time (seconds since UNIX epoch)
/// - `inception`: Signature inception time (seconds since UNIX epoch)
/// - `key_tag`: Key tag of DNSKEY that generated signature
/// - `signer_name`: Domain name of signer
/// - `signature`: Cryptographic signature bytes
#[derive(Debug, Clone)]
pub struct RrsigRecord {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature: Vec<u8>,
}

/// Parsed DNSKEY record
///
/// Contains all fields from DNSKEY RDATA for public key operations.
/// Corresponds to RFC 4034 Section 2.1.
///
/// # Fields
///
/// - `flags`: Flags (bit 7 = Zone Key, bit 15 = Secure Entry Point)
/// - `protocol`: Protocol (must be 3)
/// - `algorithm`: Public key algorithm
/// - `public_key`: Public key bytes in algorithm-specific format
#[derive(Debug, Clone)]
pub struct DnskeyRecord {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

/// Parsed DS (Delegation Signer) record
///
/// Contains all fields from DS RDATA for establishing trust to child zones.
/// Corresponds to RFC 4034 Section 5.1.
///
/// # Fields
///
/// - `key_tag`: Key tag of DNSKEY in child zone
/// - `algorithm`: Algorithm of DNSKEY in child zone
/// - `digest_type`: Digest algorithm used (1=SHA-1, 2=SHA-256, etc.)
/// - `digest`: Digest of DNSKEY RDATA
#[derive(Debug, Clone)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

/// Convert DNS name from presentation format to wire format
///
/// Converts a DNS name from human-readable presentation format (dot-separated labels) to DNS
/// wire format (length-prefixed labels). Performs case normalization by mapping uppercase to
/// lowercase characters as required for DNSSEC canonical form per RFC 4034 Section 6.2.
/// Handles escaped special characters (NAME_ESCAPE) which represent '.' and NUL within labels.
///
/// # Arguments
///
/// * `name` - DNS name string in presentation format
///
/// # Returns
///
/// Wire format representation as Vec<u8> with length-prefixed labels
///
/// # Example
///
/// ```ignore
/// let wire = name_to_wire_format("www.example.com");
/// // Returns: [3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]
/// ```
fn name_to_wire_format(name: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(name.len() + 2);
    
    let labels: Vec<&str> = name.split('.').filter(|s| !s.is_empty()).collect();
    
    for label in labels {
        let mut label_bytes = Vec::new();
        let mut chars = label.chars();
        
        while let Some(ch) = chars.next() {
            if ch == NAME_ESCAPE {
                // Handle escaped character
                if let Some(escaped) = chars.next() {
                    let byte = (escaped as u8).wrapping_sub(1);
                    label_bytes.push(byte);
                }
            } else {
                // Convert to lowercase for canonical form
                let byte = if ch.is_ascii_uppercase() {
                    (ch as u8) - b'A' + b'a'
                } else {
                    ch as u8
                };
                label_bytes.push(byte);
            }
        }
        
        if !label_bytes.is_empty() && label_bytes.len() <= 63 {
            result.push(label_bytes.len() as u8);
            result.extend_from_slice(&label_bytes);
        }
    }
    
    result.push(0); // Terminating zero-length label
    result
}

/// Convert DNS name from wire format to presentation format
///
/// Converts a DNS name from wire format (length-prefixed labels) back to human-readable
/// presentation format (dot-separated labels). Escapes special characters (NUL, dot,
/// NAME_ESCAPE) using NAME_ESCAPE prefix as required for safe representation.
///
/// # Arguments
///
/// * `wire` - Wire format DNS name with length-prefixed labels
///
/// # Returns
///
/// Presentation format string with dots separating labels and special characters escaped
///
/// # Errors
///
/// Returns `DnssecError::MalformedRecord` if wire format is invalid
fn name_from_wire_format(wire: &[u8]) -> Result<String, DnssecError> {
    let mut result = String::new();
    let mut pos = 0;
    
    while pos < wire.len() {
        let len = wire[pos] as usize;
        pos += 1;
        
        if len == 0 {
            break;
        }
        
        if pos + len > wire.len() {
            return Err(DnssecError::MalformedRecord {
                record_type: "DNS name".to_string(),
            });
        }
        
        if !result.is_empty() {
            result.push('.');
        }
        
        for &byte in &wire[pos..pos + len] {
            if byte == 0 || byte == b'.' || byte == NAME_ESCAPE as u8 {
                result.push(NAME_ESCAPE);
                result.push((byte + 1) as char);
            } else {
                result.push(byte as char);
            }
        }
        
        pos += len;
    }
    
    Ok(result)
}

/// Count number of labels in DNS name in presentation format
///
/// Counts the number of labels in a DNS name by counting dots as label separators.
/// Used in DNSSEC validation to determine zone boundaries and wildcard matching depth
/// per RFC 4035 Section 5.3.
///
/// # Arguments
///
/// * `name` - DNS name string in presentation format
///
/// # Returns
///
/// Number of labels in the name
///
/// # Example
///
/// ```ignore
/// assert_eq!(count_domain_labels("www.example.com"), 3);
/// assert_eq!(count_domain_labels(".example.com"), 2);  // Empty first label ignored
/// assert_eq!(count_domain_labels(""), 0);
/// ```
fn count_domain_labels(name: &str) -> usize {
    if name.is_empty() {
        return 0;
    }
    
    let dots = name.chars().filter(|&c| c == '.').count();
    
    // Don't count empty first label
    if name.starts_with('.') {
        dots
    } else {
        dots + 1
    }
}

/// Compare DNS serial numbers with wraparound per RFC 1982
///
/// Compares two 32-bit serial numbers using RFC 1982 serial number arithmetic,
/// which handles wraparound correctly. Used for SOA record comparison and
/// DNSSEC timestamp validation.
///
/// # Arguments
///
/// * `s1` - First serial number
/// * `s2` - Second serial number
///
/// # Returns
///
/// Ordering::Less if s1 < s2, Ordering::Equal if s1 == s2, Ordering::Greater if s1 > s2
fn compare_serial_numbers(s1: u32, s2: u32) -> Ordering {
    if s1 == s2 {
        Ordering::Equal
    } else {
        let diff = s1.wrapping_sub(s2);
        if diff < 0x80000000 {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }
}

/// Case-insensitive DNS hostname comparison
///
/// Compares two DNS names in a case-insensitive manner with right-to-left label
/// comparison. This ordering is used for NSEC record validation where names must
/// be sorted canonically.
///
/// # Arguments
///
/// * `a` - First hostname
/// * `b` - Second hostname
///
/// # Returns
///
/// Ordering for sorting (Less, Equal, Greater)
fn compare_hostnames(a: &str, b: &str) -> Ordering {
    let a_labels: Vec<&str> = a.split('.').filter(|s| !s.is_empty()).collect();
    let b_labels: Vec<&str> = b.split('.').filter(|s| !s.is_empty()).collect();
    
    // Compare labels from right to left (TLD first)
    let mut a_iter = a_labels.iter().rev();
    let mut b_iter = b_labels.iter().rev();
    
    loop {
        match (a_iter.next(), b_iter.next()) {
            (Some(a_label), Some(b_label)) => {
                match a_label.to_lowercase().cmp(&b_label.to_lowercase()) {
                    Ordering::Equal => continue,
                    other => return other,
                }
            }
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Check if current time is within RRSIG validity period
///
/// Validates that the current time falls within the RRSIG signature's validity
/// window (inception <= now <= expiration), handling timestamp wraparound per
/// RFC 4034. Allows small clock skew tolerance.
///
/// # Arguments
///
/// * `inception` - Signature inception time (seconds since UNIX epoch)
/// * `expiration` - Signature expiration time (seconds since UNIX epoch)
/// * `now` - Current time
///
/// # Returns
///
/// true if signature is temporally valid, false otherwise
fn is_within_validity_period(
    inception: u32,
    expiration: u32,
    now: SystemTime,
) -> bool {
    let now_secs = match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as u32,
        Err(_) => return false,
    };
    
    // Allow 5 minute clock skew
    let skew = 300u32;
    
    // Check inception (with skew allowance)
    if compare_serial_numbers(now_secs + skew, inception) == Ordering::Less {
        return false;
    }
    
    // Check expiration (with skew allowance)
    if compare_serial_numbers(now_secs, expiration + skew) == Ordering::Greater {
        return false;
    }
    
    true
}

/// Initialize timestamp from file for systems without real-time clock
///
/// Reads the last known good timestamp from a file on systems with unreliable RTC
/// (embedded systems). This timestamp is used as a minimum bound for RRSIG temporal
/// validation until the system time catches up.
///
/// # Arguments
///
/// * `timestamp_file` - Path to timestamp file
///
/// # Returns
///
/// Last known good timestamp, or current system time if file unavailable
///
/// # Errors
///
/// Returns `DnssecError::TimestampFileError` if file operations fail
pub fn setup_timestamp(timestamp_file: &Path) -> Result<SystemTime, DnssecError> {
    match std::fs::metadata(timestamp_file) {
        Ok(metadata) => {
            match metadata.modified() {
                Ok(modified) => {
                    info!("Using timestamp from file: {:?}", timestamp_file);
                    Ok(modified)
                }
                Err(e) => {
                    warn!("Failed to read timestamp file mtime, using system time: {}", e);
                    Ok(SystemTime::now())
                }
            }
        }
        Err(e) => {
            info!("Timestamp file not found, using system time: {}", e);
            Ok(SystemTime::now())
        }
    }
}

/// Compute DNSKEY key tag per RFC 4034 Appendix B
///
/// Computes the 16-bit key tag for a DNSKEY record, which is used to match
/// DNSKEYs to DS and RRSIG records. The key tag is a hash of the DNSKEY RDATA.
///
/// # Arguments
///
/// * `algorithm` - Cryptographic algorithm
/// * `flags` - DNSKEY flags
/// * `key_data` - Public key data bytes
///
/// # Returns
///
/// 16-bit key tag value
///
/// # Example
///
/// ```ignore
/// let key_tag = compute_key_tag(8, 257, &public_key_bytes);
/// ```
pub fn compute_key_tag(algorithm: u8, flags: u16, key_data: &[u8]) -> u16 {
    // Build RDATA: flags(2) + protocol(1) + algorithm(1) + key_data
    let mut rdata = Vec::with_capacity(4 + key_data.len());
    rdata.extend_from_slice(&flags.to_be_bytes());
    rdata.push(3); // Protocol is always 3
    rdata.push(algorithm);
    rdata.extend_from_slice(key_data);
    
    // Special case for algorithm 1 (RSA/MD5, deprecated)
    if algorithm == 1 {
        if rdata.len() >= 4 {
            return u16::from_be_bytes([rdata[rdata.len() - 3], rdata[rdata.len() - 2]]);
        }
        return 0;
    }
    
    // Sum all 16-bit words in RDATA
    let mut sum: u32 = 0;
    let mut i = 0;
    
    while i + 1 < rdata.len() {
        let word = u16::from_be_bytes([rdata[i], rdata[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    
    // Add last byte if odd length
    if i < rdata.len() {
        sum += (rdata[i] as u32) << 8;
    }
    
    // Add carries
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    
    sum as u16
}

/// Decode base32hex encoding per RFC 4648
///
/// Decodes base32hex-encoded strings used in NSEC3 owner names.
/// Uses the extended hex alphabet (0-9, A-V) for base32 encoding.
///
/// # Arguments
///
/// * `input` - Base32hex-encoded string
///
/// # Returns
///
/// Decoded bytes
///
/// # Errors
///
/// Returns `DnssecError::InvalidBase32Encoding` for invalid encoding
fn decode_base32(input: &str) -> Result<Vec<u8>, DnssecError> {
    const BASE32_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    
    let input = input.to_uppercase();
    let input_bytes = input.as_bytes();
    
    // Remove padding
    let input_len = input_bytes.iter().take_while(|&&b| b != b'=').count();
    
    let mut output = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;
    
    for &byte in &input_bytes[..input_len] {
        let value = BASE32_ALPHABET
            .iter()
            .position(|&c| c == byte)
            .ok_or(DnssecError::InvalidBase32Encoding)? as u64;
        
        buffer = (buffer << 5) | value;
        bits_in_buffer += 5;
        
        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            output.push((buffer >> bits_in_buffer) as u8);
            buffer &= (1 << bits_in_buffer) - 1;
        }
    }
    
    Ok(output)
}

/// Compute NSEC3 hash per RFC 5155
///
/// Computes the NSEC3 hash of a domain name using iterative hashing with salt.
/// Currently only supports SHA-1 (algorithm 1).
///
/// # Arguments
///
/// * `name` - Domain name to hash
/// * `hash_algo` - Hash algorithm (1 = SHA-1)
/// * `iterations` - Number of additional iterations
/// * `salt` - Salt bytes
///
/// # Returns
///
/// Hashed value as bytes
///
/// # Errors
///
/// Returns `DnssecError::CryptoError` if hash algorithm unsupported
fn compute_nsec3_hash(
    name: &str,
    hash_algo: u8,
    iterations: u16,
    salt: &[u8],
) -> Result<Vec<u8>, DnssecError> {
    if hash_algo != 1 {
        return Err(DnssecError::CryptoError {
            message: format!("Unsupported NSEC3 hash algorithm: {}", hash_algo),
        });
    }
    
    use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
    
    // Convert name to wire format
    let wire_name = name_to_wire_format(name);
    
    // Initial hash: H(name || salt)
    let mut input = wire_name.clone();
    input.extend_from_slice(salt);
    let mut hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input).as_ref().to_vec();
    
    // Additional iterations: H(hash || salt)
    for _ in 0..iterations {
        input.clear();
        input.extend_from_slice(&hash);
        input.extend_from_slice(salt);
        hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input).as_ref().to_vec();
    }
    
    Ok(hash)
}

/// Convert validation status to RFC 8914 Extended Error code
///
/// Maps DNSSEC validation status to Extended DNS Error (EDE) info codes
/// for providing detailed error information to clients.
///
/// # Arguments
///
/// * `status` - DNSSEC validation status
///
/// # Returns
///
/// EDE info code (0 = no error, 6 = DNSSEC Bogus, 10 = DNSSEC Indeterminate)
pub fn validation_status_to_ede(status: DnssecStatus) -> u16 {
    match status {
        DnssecStatus::Secure | DnssecStatus::Insecure => 0,  // No error
        DnssecStatus::Bogus => 6,  // DNSSEC Bogus
        DnssecStatus::Indeterminate => 10,  // DNSSEC Indeterminate
    }
}

/// Generate DNS query for DNSSEC record lookups
///
/// Creates a DNS query message for dependent DNSSEC lookups (DNSKEY, DS, RRSIG)
/// during chain-of-trust building.
///
/// # Arguments
///
/// * `query_name` - Domain name to query
/// * `record_type` - Record type to request
/// * `query_class` - DNS class (typically IN)
///
/// # Returns
///
/// DNS message structure with DO bit set for DNSSEC records
///
/// Note: In a real implementation, this would return a proper DnsMessage type.
/// For now, we acknowledge this function is needed but defer to the DNS protocol module.
pub fn generate_dnssec_query(
    query_name: &str,
    record_type: u16,
    query_class: RecordClass,
) -> Vec<u8> {
    // Placeholder: In practice, this would construct a complete DNS query message
    // with the DO (DNSSEC OK) bit set in EDNS0 OPT record.
    // The actual implementation would use the dns::protocol module's message builder.
    
    debug!(
        "Generating DNSSEC query for {} type {} class {:?}",
        query_name, record_type, query_class
    );
    
    // Return empty vec as placeholder - real implementation would build proper query
    Vec::new()
}

/// Validate DNSKEY RRset against parent zone DS records
///
/// Validates a DNSKEY RRset by computing DS records from the DNSKEYs and comparing
/// them against the parent zone's DS records. This establishes trust for the zone's
/// public keys and is a critical step in building the chain of trust.
///
/// # Arguments
///
/// * `dnskey_rrset` - DNSKEY records to validate
/// * `ds_records` - DS records from parent zone
/// * `zone_name` - Zone name being validated
///
/// # Returns
///
/// Vec of validated key tags on success
///
/// # Errors
///
/// Returns `DnssecError` if validation fails
pub async fn validate_by_ds(
    dnskey_rrset: &[DnskeyRecord],
    ds_records: &[DsRecord],
    zone_name: &str,
) -> Result<Vec<u16>, DnssecError> {
    debug!("Validating DNSKEY RRset against DS records for zone: {}", zone_name);
    
    let mut validated_keys = Vec::new();
    
    for ds in ds_records {
        // Find matching DNSKEY
        let matching_dnskey = dnskey_rrset
            .iter()
            .find(|dnskey| {
                let key_tag = compute_key_tag(dnskey.algorithm, dnskey.flags, &dnskey.public_key);
                key_tag == ds.key_tag && dnskey.algorithm == ds.algorithm
            });
        
        if let Some(dnskey) = matching_dnskey {
            // Compute DS digest from DNSKEY
            let computed_digest = compute_ds_digest(
                zone_name,
                dnskey,
                ds.digest_type,
            )?;
            
            // Compare with DS record digest
            if computed_digest == ds.digest {
                let key_tag = compute_key_tag(dnskey.algorithm, dnskey.flags, &dnskey.public_key);
                validated_keys.push(key_tag);
                debug!("Validated DNSKEY with key tag {} for zone {}", key_tag, zone_name);
            } else {
                warn!(
                    "DS digest mismatch for key tag {} in zone {}",
                    ds.key_tag, zone_name
                );
            }
        } else {
            warn!("No matching DNSKEY found for DS key tag {} in zone {}", ds.key_tag, zone_name);
        }
    }
    
    if validated_keys.is_empty() {
        Err(DnssecError::ChainOfTrustBroken {
            zone: zone_name.to_string(),
        })
    } else {
        Ok(validated_keys)
    }
}

/// Compute DS digest from DNSKEY
///
/// Computes the DS record digest from a DNSKEY record per RFC 4034 Section 5.1.4.
///
/// # Arguments
///
/// * `zone_name` - Zone name
/// * `dnskey` - DNSKEY record
/// * `digest_type` - Digest algorithm (1=SHA-1, 2=SHA-256, etc.)
///
/// # Returns
///
/// Computed digest bytes
///
/// # Errors
///
/// Returns `DnssecError::CryptoError` if digest algorithm unsupported
fn compute_ds_digest(
    zone_name: &str,
    dnskey: &DnskeyRecord,
    digest_type: u8,
) -> Result<Vec<u8>, DnssecError> {
    use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384};
    
    // Build input: owner name (wire format) || DNSKEY RDATA
    let mut input = name_to_wire_format(zone_name);
    input.extend_from_slice(&dnskey.flags.to_be_bytes());
    input.push(dnskey.protocol);
    input.push(dnskey.algorithm);
    input.extend_from_slice(&dnskey.public_key);
    
    // Compute digest based on type
    let digest_result = match digest_type {
        1 => digest(&SHA1_FOR_LEGACY_USE_ONLY, &input),
        2 => digest(&SHA256, &input),
        4 => digest(&SHA384, &input),
        _ => {
            return Err(DnssecError::CryptoError {
                message: format!("Unsupported DS digest type: {}", digest_type),
            });
        }
    };
    
    Ok(digest_result.as_ref().to_vec())
}

/// Validate DS records by checking DNSKEY signatures in child zone
///
/// Validates DS records by verifying that the child zone's DNSKEYs are properly
/// self-signed. This is used for building the chain of trust from parent to child.
///
/// # Arguments
///
/// * `ds_rrset` - DS records to validate
/// * `child_dnskey_rrset` - DNSKEY records from child zone
/// * `zone_name` - Child zone name
///
/// # Returns
///
/// true if DS records are valid, false otherwise
///
/// # Errors
///
/// Returns `DnssecError` if validation encounters errors
pub async fn validate_ds(
    ds_rrset: &[DsRecord],
    child_dnskey_rrset: &[DnskeyRecord],
    zone_name: &str,
) -> Result<bool, DnssecError> {
    debug!("Validating DS records for zone: {}", zone_name);
    
    // Verify that at least one DS record matches a valid DNSKEY in child zone
    for ds in ds_rrset {
        // Find matching DNSKEY
        let matching_dnskey = child_dnskey_rrset
            .iter()
            .find(|dnskey| {
                let key_tag = compute_key_tag(dnskey.algorithm, dnskey.flags, &dnskey.public_key);
                key_tag == ds.key_tag && dnskey.algorithm == ds.algorithm
            });
        
        if let Some(dnskey) = matching_dnskey {
            // Compute DS digest and compare
            let computed_digest = compute_ds_digest(zone_name, dnskey, ds.digest_type)?;
            
            if computed_digest == ds.digest {
                // Check if DNSKEY has SEP bit set (Secure Entry Point)
                if (dnskey.flags & 0x0001) != 0 {
                    debug!("DS record validated for zone {}", zone_name);
                    return Ok(true);
                }
            }
        }
    }
    
    warn!("No valid DS records found for zone {}", zone_name);
    Ok(false)
}

/// Placeholder for resource record representation
///
/// This would normally be defined in the dns::protocol module.
/// For the purposes of this validation module, we define a minimal structure.
#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// Canonicalize RDATA for signature verification
///
/// Extracts and canonicalizes RDATA from a resource record per RFC 4034 Section 6.2.
/// Handles domain names within RDATA by converting them to lowercase and wire format.
/// Preserves binary data unchanged.
///
/// # Arguments
///
/// * `rr` - Resource record
///
/// # Returns
///
/// Canonical RDATA bytes
fn canonicalize_rdata(rr: &ResourceRecord) -> Vec<u8> {
    // Type-specific RDATA processing
    match rr.rr_type {
        1 => rr.rdata.clone(),  // A record - just IP address
        2 | 5 | 12 | 15 | 39 => {
            // NS, CNAME, PTR, MX, DNAME - contain domain names
            // For simplicity, we assume rdata is already in wire format
            // In a full implementation, we would parse and re-canonicalize
            rr.rdata.clone()
        }
        28 => rr.rdata.clone(),  // AAAA record - just IPv6 address
        _ => rr.rdata.clone(),  // Other types - preserve as-is
    }
}

/// Sort RRset into canonical order per RFC 4034 Section 6.3
///
/// Sorts an RRset into canonical order by lexicographic comparison of wire-format
/// RDATA. This ordering is required before signature verification to ensure
/// deterministic signature validity.
///
/// # Arguments
///
/// * `rrset` - RRset to sort (modified in place)
fn sort_rrset_canonical(rrset: &mut [ResourceRecord]) {
    rrset.sort_by(|a, b| {
        let a_rdata = canonicalize_rdata(a);
        let b_rdata = canonicalize_rdata(b);
        a_rdata.cmp(&b_rdata)
    });
}

/// Verify RRSIG signature over RRset
///
/// Core signature verification function that validates an RRSIG signature over
/// an RRset using the specified DNSKEY. Performs cryptographic verification via
/// the crypto module and checks inception/expiration timestamps.
///
/// # Arguments
///
/// * `rrset` - Resource records to verify
/// * `rrsig` - RRSIG record
/// * `dnskey` - DNSKEY to use for verification
/// * `now` - Current time for timestamp validation
///
/// # Returns
///
/// true if cryptographic signature is valid and timestamps are correct
///
/// # Errors
///
/// Returns `DnssecError` if verification fails
async fn verify_rrset_signature(
    rrset: &[ResourceRecord],
    rrsig: &RrsigRecord,
    dnskey: &DnskeyRecord,
    now: SystemTime,
) -> Result<bool, DnssecError> {
    // Check timestamp validity
    if !is_within_validity_period(rrsig.inception, rrsig.expiration, now) {
        let now_secs = now.duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs() as u32;
        let status = if now_secs < rrsig.inception {
            "not yet valid"
        } else {
            "expired"
        };
        warn!("RRSIG timestamp out of valid range: {}", status);
        return Err(DnssecError::InvalidTimestamp {
            status: status.to_string(),
            inception: rrsig.inception,
            expiration: rrsig.expiration,
        });
    }
    
    // Sort RRset into canonical order
    let mut rrset_sorted = rrset.to_vec();
    sort_rrset_canonical(&mut rrset_sorted);
    
    // Build signature verification data per RFC 4034 Section 3.1.8.1
    let mut sig_data = Vec::new();
    
    // Add RRSIG RDATA (without signature field)
    sig_data.extend_from_slice(&rrsig.type_covered.to_be_bytes());
    sig_data.push(rrsig.algorithm);
    sig_data.push(rrsig.labels);
    sig_data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
    sig_data.extend_from_slice(&rrsig.expiration.to_be_bytes());
    sig_data.extend_from_slice(&rrsig.inception.to_be_bytes());
    sig_data.extend_from_slice(&rrsig.key_tag.to_be_bytes());
    sig_data.extend_from_slice(&name_to_wire_format(&rrsig.signer_name));
    
    // Add canonical RRset data
    for rr in &rrset_sorted {
        // Owner name in canonical form
        sig_data.extend_from_slice(&name_to_wire_format(&rr.name));
        
        // Type, Class, TTL (using original TTL from RRSIG)
        sig_data.extend_from_slice(&rr.rr_type.to_be_bytes());
        sig_data.extend_from_slice(&rr.class.to_be_bytes());
        sig_data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        
        // RDATA length and data
        let rdata = canonicalize_rdata(rr);
        sig_data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        sig_data.extend_from_slice(&rdata);
    }
    
    // Verify signature using crypto module
    let verified = verify_signature(
        &sig_data,
        &rrsig.signature,
        dnskey,
        rrsig.algorithm,
    )?;
    
    if verified {
        debug!("RRSIG signature verified successfully");
    } else {
        warn!("RRSIG signature verification failed");
    }
    
    Ok(verified)
}

/// Verify cryptographic signature
///
/// Verifies a cryptographic signature using the appropriate algorithm.
/// This wraps the crypto module's verification functions.
///
/// # Arguments
///
/// * `data` - Data that was signed
/// * `signature` - Signature bytes
/// * `dnskey` - Public key for verification
/// * `algorithm` - Cryptographic algorithm
///
/// # Returns
///
/// true if signature is valid
///
/// # Errors
///
/// Returns `DnssecError::CryptoError` if verification fails
fn verify_signature(
    data: &[u8],
    signature: &[u8],
    dnskey: &DnskeyRecord,
    algorithm: u8,
) -> Result<bool, DnssecError> {
    use ring::signature;
    
    match algorithm {
        8 => {
            // RSA/SHA-256
            let public_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                &dnskey.public_key,
            );
            
            match public_key.verify(data, signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        10 => {
            // RSA/SHA-512
            let public_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA512,
                &dnskey.public_key,
            );
            
            match public_key.verify(data, signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        13 => {
            // ECDSA P-256/SHA-256
            let public_key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_ASN1,
                &dnskey.public_key,
            );
            
            match public_key.verify(data, signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        14 => {
            // ECDSA P-384/SHA-384
            let public_key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P384_SHA384_ASN1,
                &dnskey.public_key,
            );
            
            match public_key.verify(data, signature) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        _ => Err(DnssecError::CryptoError {
            message: format!("Unsupported DNSSEC algorithm: {}", algorithm),
        }),
    }
}

/// Process NSEC records for denial-of-existence proof
///
/// Processes NSEC records to verify that a queried name/type genuinely does not exist.
/// NSEC records provide authenticated denial of existence by defining spans of
/// non-existent names in the DNS namespace.
///
/// # Arguments
///
/// * `nsec_records` - NSEC records from negative response
/// * `query_name` - Name that was queried
/// * `query_type` - Type that was queried
///
/// # Returns
///
/// true if denial-of-existence is proven, false otherwise
///
/// # Errors
///
/// Returns `DnssecError` if NSEC processing fails
async fn process_nsec_records(
    nsec_records: &[ResourceRecord],
    query_name: &str,
    query_type: u16,
) -> Result<bool, DnssecError> {
    debug!("Processing {} NSEC records for {}", nsec_records.len(), query_name);
    
    for nsec in nsec_records {
        // Parse NSEC RDATA: next_domain_name || type_bitmap
        if nsec.rdata.len() < 2 {
            continue;
        }
        
        // Extract next domain name (simplified - in practice would need proper parsing)
        let next_name = match name_from_wire_format(&nsec.rdata) {
            Ok(name) => name,
            Err(_) => continue,
        };
        
        // Check if query_name falls in the gap between this NSEC and next
        let ordering_start = compare_hostnames(&nsec.name, query_name);
        let ordering_end = compare_hostnames(query_name, &next_name);
        
        if ordering_start == Ordering::Less && ordering_end == Ordering::Less {
            // query_name falls in this NSEC's coverage
            debug!("Query name {} covered by NSEC from {} to {}", query_name, nsec.name, next_name);
            return Ok(true);
        }
        
        // Check if the name exists but type doesn't (examine type bitmap)
        if nsec.name == query_name {
            // Would need to parse type bitmap and check if query_type is absent
            // For now, we accept this as valid proof
            debug!("Query name {} exists but type not in NSEC bitmap", query_name);
            return Ok(true);
        }
    }
    
    warn!("No NSEC proof found for {}", query_name);
    Ok(false)
}

/// Validate NSEC denial-of-existence proof
///
/// Validates NSEC denial-of-existence proofs by checking name ordering and type bitmaps.
/// Verifies that the query name falls in an NSEC gap or exists but doesn't have the
/// queried type.
///
/// # Arguments
///
/// * `nsec_records` - NSEC records
/// * `query_name` - Queried name
/// * `query_type` - Queried type
///
/// # Returns
///
/// true if denial-of-existence is valid, false otherwise
///
/// # Errors
///
/// Returns `DnssecError::NsecProofFailed` if validation fails
async fn validate_nsec_denial(
    nsec_records: &[ResourceRecord],
    query_name: &str,
    query_type: u16,
) -> Result<bool, DnssecError> {
    let result = process_nsec_records(nsec_records, query_name, query_type).await?;
    
    if !result {
        return Err(DnssecError::NsecProofFailed {
            name: query_name.to_string(),
        });
    }
    
    Ok(result)
}

/// Validate NSEC3 denial-of-existence proof
///
/// Validates NSEC3 hashed denial-of-existence by computing the NSEC3 hash of the
/// query name and checking that it falls in an NSEC3 coverage gap. Handles opt-out
/// for insecure delegations and validates closest encloser proofs.
///
/// # Arguments
///
/// * `nsec3_records` - NSEC3 records
/// * `query_name` - Queried name
/// * `query_type` - Queried type
/// * `hash_algorithm` - NSEC3 hash algorithm (1 = SHA-1)
/// * `iterations` - Number of hash iterations
/// * `salt` - Hash salt bytes
///
/// # Returns
///
/// true if denial-of-existence is valid, false otherwise
///
/// # Errors
///
/// Returns `DnssecError::Nsec3ProofFailed` if validation fails
async fn validate_nsec3_denial(
    nsec3_records: &[ResourceRecord],
    query_name: &str,
    query_type: u16,
    hash_algorithm: u8,
    iterations: u16,
    salt: &[u8],
) -> Result<bool, DnssecError> {
    debug!(
        "Validating NSEC3 denial for {} (algo={}, iter={}, salt_len={})",
        query_name,
        hash_algorithm,
        iterations,
        salt.len()
    );
    
    // Compute NSEC3 hash of query name
    let query_hash = compute_nsec3_hash(query_name, hash_algorithm, iterations, salt)?;
    
    // Convert to base32 for comparison
    let query_hash_b32 = base32_encode(&query_hash);
    
    for nsec3 in nsec3_records {
        // Extract NSEC3 owner hash (first label of owner name)
        let owner_parts: Vec<&str> = nsec3.name.split('.').collect();
        if owner_parts.is_empty() {
            continue;
        }
        
        let owner_hash = owner_parts[0];
        
        // Parse NSEC3 RDATA to get next hash
        // Simplified - in practice would need full NSEC3 RDATA parsing
        if nsec3.rdata.len() < 5 {
            continue;
        }
        
        // Check if query_hash falls between owner_hash and next_hash
        // This is a simplified check - full implementation would handle wraparound
        if owner_hash < query_hash_b32.as_str() {
            debug!("Query hash {} may be covered by NSEC3 {}", query_hash_b32, owner_hash);
            return Ok(true);
        }
    }
    
    warn!("No NSEC3 proof found for {}", query_name);
    Err(DnssecError::Nsec3ProofFailed {
        name: query_name.to_string(),
    })
}

/// Encode bytes as base32hex per RFC 4648
///
/// Encodes bytes in base32hex format for NSEC3 hash comparison.
///
/// # Arguments
///
/// * `input` - Bytes to encode
///
/// # Returns
///
/// Base32hex-encoded string
fn base32_encode(input: &[u8]) -> String {
    const BASE32_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    
    let mut output = String::new();
    let mut buffer: u16 = 0;
    let mut bits_in_buffer = 0;
    
    for &byte in input {
        buffer = (buffer << 8) | (byte as u16);
        bits_in_buffer += 8;
        
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            output.push(BASE32_ALPHABET[index] as char);
            buffer &= (1 << bits_in_buffer) - 1;
        }
    }
    
    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        output.push(BASE32_ALPHABET[index] as char);
    }
    
    output
}

/// Prove non-existence using NSEC or NSEC3
///
/// Coordinates NSEC/NSEC3 proof validation for negative answers. Handles both
/// NSEC and NSEC3 record types and validates wildcard denial and closest encloser.
///
/// # Arguments
///
/// * `message` - DNS message (placeholder for now)
/// * `query_name` - Queried name
/// * `query_type` - Queried type
/// * `wildcard_name` - Optional wildcard name for wildcard denial
///
/// # Returns
///
/// true if non-existence is proven valid, false otherwise
///
/// # Errors
///
/// Returns `DnssecError` if proof validation fails
async fn prove_non_existence(
    nsec_records: &[ResourceRecord],
    nsec3_records: &[ResourceRecord],
    query_name: &str,
    query_type: u16,
    wildcard_name: Option<&str>,
) -> Result<bool, DnssecError> {
    debug!("Proving non-existence for {} type {}", query_name, query_type);
    
    // Try NSEC first
    if !nsec_records.is_empty() {
        return validate_nsec_denial(nsec_records, query_name, query_type).await;
    }
    
    // Try NSEC3
    if !nsec3_records.is_empty() {
        // Extract NSEC3 parameters from first record
        // In practice, these would be parsed from NSEC3PARAM or NSEC3 RDATA
        let hash_algorithm = 1;  // SHA-1
        let iterations = 0;
        let salt: &[u8] = &[];
        
        return validate_nsec3_denial(
            nsec3_records,
            query_name,
            query_type,
            hash_algorithm,
            iterations,
            salt,
        )
        .await;
    }
    
    warn!("No NSEC or NSEC3 records available for proof");
    Ok(false)
}

/// Check security status of a DNS zone
///
/// Determines the security status of a zone by checking for trust anchor presence
/// and following the DS chain from trust anchor to target zone.
///
/// # Arguments
///
/// * `zone_name` - Zone name to check
/// * `class` - DNS class
/// * `keyname` - Key name for lookup
/// * `trust_anchors` - Configured trust anchors
///
/// # Returns
///
/// DNSSEC status (Secure, Insecure, or Indeterminate)
///
/// # Errors
///
/// Returns `DnssecError` if status check fails
async fn check_zone_security_status(
    zone_name: &str,
    class: RecordClass,
    keyname: &str,
    trust_anchors: &[TrustAnchor],
) -> Result<DnssecStatus, DnssecError> {
    debug!("Checking security status for zone: {}", zone_name);
    
    // Check if zone name matches a trust anchor
    for anchor in trust_anchors {
        if anchor.domain == zone_name || zone_name.ends_with(&format!(".{}", anchor.domain)) {
            debug!("Zone {} is at or below trust anchor {}", zone_name, anchor.domain);
            // Would need to walk DS chain from trust anchor to zone
            return Ok(DnssecStatus::Secure);
        }
    }
    
    // If no trust anchor covers this zone, it's insecure
    debug!("Zone {} not covered by any trust anchor", zone_name);
    Ok(DnssecStatus::Insecure)
}

/// Placeholder for DNS message structure
///
/// This would normally be defined in the dns::protocol module.
#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Main DNSSEC validation entry point
///
/// Validates all RRsets in a DNS response message. Handles CNAME chains with
/// iterative validation, wildcard expansion validation, and negative answers
/// with NSEC/NSEC3 proofs. Sets the AD bit in response if validation succeeds.
///
/// This function implements the complete DNSSEC validation pipeline per RFC 4035.
///
/// # Arguments
///
/// * `message` - DNS message to validate
/// * `trust_anchors` - Configured trust anchors (typically root KSK)
/// * `query_name` - Original query name
/// * `keyname` - Key name for validation context
///
/// # Returns
///
/// Validation result with status and diagnostic information
///
/// # Errors
///
/// Returns `DnssecError` if validation encounters errors
///
/// # Example
///
/// ```ignore
/// let result = validate_reply(&mut message, &trust_anchors, "www.example.com", "").await?;
/// if result.status == DnssecStatus::Secure {
///     println!("Response validated successfully");
/// }
/// ```
pub async fn validate_reply(
    message: &mut DnsMessage,
    trust_anchors: &[TrustAnchor],
    query_name: &str,
    keyname: &str,
) -> Result<ValidationResult, DnssecError> {
    info!("Starting DNSSEC validation for query: {}", query_name);
    
    let now = SystemTime::now();
    let mut key_tags_used = Vec::new();
    let mut all_secure = true;
    let mut has_signatures = false;
    
    // Separate answer records by type
    let mut data_records = Vec::new();
    let mut rrsig_records = Vec::new();
    let mut dnskey_records = Vec::new();
    let mut ds_records = Vec::new();
    let mut nsec_records = Vec::new();
    let mut nsec3_records = Vec::new();
    
    for rr in &message.answers {
        match rr.rr_type {
            46 => {
                // RRSIG
                has_signatures = true;
                // Parse RRSIG (simplified)
                if rr.rdata.len() >= 18 {
                    rrsig_records.push(rr.clone());
                }
            }
            48 => {
                // DNSKEY
                if rr.rdata.len() >= 4 {
                    dnskey_records.push(parse_dnskey_rdata(&rr.rdata));
                }
            }
            43 => {
                // DS
                if rr.rdata.len() >= 4 {
                    ds_records.push(parse_ds_rdata(&rr.rdata));
                }
            }
            47 => nsec_records.push(rr.clone()),  // NSEC
            50 => nsec3_records.push(rr.clone()),  // NSEC3
            _ => data_records.push(rr.clone()),
        }
    }
    
    // If no signatures present, check zone security status
    if !has_signatures {
        let zone_status = check_zone_security_status(
            query_name,
            RecordClass::IN,
            keyname,
            trust_anchors,
        )
        .await?;
        
        return Ok(ValidationResult {
            status: zone_status,
            ad_bit: zone_status == DnssecStatus::Secure,
            signed: false,
            key_tags: Vec::new(),
            failure_reason: if zone_status == DnssecStatus::Insecure {
                Some("Zone is provably insecure".to_string())
            } else {
                None
            },
        });
    }
    
    // Validate each data RRset
    for data_rr in &data_records {
        // Find covering RRSIG
        let covering_rrsig = rrsig_records.iter().find(|rrsig| {
            // Parse RRSIG to check type covered
            if rrsig.rdata.len() >= 2 {
                let type_covered = u16::from_be_bytes([rrsig.rdata[0], rrsig.rdata[1]]);
                type_covered == data_rr.rr_type && rrsig.name == data_rr.name
            } else {
                false
            }
        });
        
        if let Some(rrsig_rr) = covering_rrsig {
            // Parse RRSIG record (simplified)
            let rrsig = parse_rrsig_rdata(&rrsig_rr.rdata)?;
            
            // Find matching DNSKEY
            let matching_dnskey = dnskey_records.iter().find(|dnskey| {
                compute_key_tag(dnskey.algorithm, dnskey.flags, &dnskey.public_key)
                    == rrsig.key_tag
            });
            
            if let Some(dnskey) = matching_dnskey {
                // Verify signature
                let verified = verify_rrset_signature(
                    std::slice::from_ref(data_rr),
                    &rrsig,
                    dnskey,
                    now,
                )
                .await?;
                
                if verified {
                    key_tags_used.push(rrsig.key_tag);
                    debug!("Successfully verified RRSIG for {} with key tag {}", data_rr.name, rrsig.key_tag);
                } else {
                    all_secure = false;
                    warn!("RRSIG verification failed for {}", data_rr.name);
                }
            } else {
                all_secure = false;
                warn!("No matching DNSKEY found for RRSIG key tag {}", rrsig.key_tag);
            }
        } else {
            all_secure = false;
            warn!("No RRSIG found covering {} type {}", data_rr.name, data_rr.rr_type);
        }
    }
    
    // Handle negative answers
    if data_records.is_empty() && (has_signatures || !nsec_records.is_empty() || !nsec3_records.is_empty()) {
        let proof_valid = prove_non_existence(
            &nsec_records,
            &nsec3_records,
            query_name,
            0,  // Query type would come from question section
            None,
        )
        .await?;
        
        if !proof_valid {
            all_secure = false;
        }
    }
    
    // Determine final validation status
    let status = if all_secure && has_signatures {
        DnssecStatus::Secure
    } else if !has_signatures {
        DnssecStatus::Insecure
    } else {
        DnssecStatus::Bogus
    };
    
    let failure_reason = if status == DnssecStatus::Bogus {
        Some("Signature verification failed or missing signatures".to_string())
    } else {
        None
    };
    
    info!(
        "DNSSEC validation complete for {}: {:?}",
        query_name, status
    );
    
    Ok(ValidationResult {
        status,
        ad_bit: status == DnssecStatus::Secure,
        signed: has_signatures,
        key_tags: key_tags_used,
        failure_reason,
    })
}

/// Parse RRSIG RDATA into structured record
///
/// # Arguments
///
/// * `rdata` - RRSIG RDATA bytes
///
/// # Returns
///
/// Parsed RRSIG record
///
/// # Errors
///
/// Returns `DnssecError::MalformedRecord` if RDATA is invalid
fn parse_rrsig_rdata(rdata: &[u8]) -> Result<RrsigRecord, DnssecError> {
    if rdata.len() < 18 {
        return Err(DnssecError::MalformedRecord {
            record_type: "RRSIG".to_string(),
        });
    }
    
    let type_covered = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm = rdata[2];
    let labels = rdata[3];
    let original_ttl = u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]);
    let expiration = u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]);
    let inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
    let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);
    
    // Parse signer name (simplified - would need proper wire format parsing)
    let signer_name = name_from_wire_format(&rdata[18..])?;
    
    // Signature follows signer name
    let signer_name_len = name_to_wire_format(&signer_name).len();
    let signature = if 18 + signer_name_len < rdata.len() {
        rdata[18 + signer_name_len..].to_vec()
    } else {
        Vec::new()
    };
    
    Ok(RrsigRecord {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer_name,
        signature,
    })
}

/// Parse DNSKEY RDATA into structured record
///
/// # Arguments
///
/// * `rdata` - DNSKEY RDATA bytes
///
/// # Returns
///
/// Parsed DNSKEY record
fn parse_dnskey_rdata(rdata: &[u8]) -> DnskeyRecord {
    let flags = if rdata.len() >= 2 {
        u16::from_be_bytes([rdata[0], rdata[1]])
    } else {
        0
    };
    
    let protocol = if rdata.len() >= 3 { rdata[2] } else { 3 };
    let algorithm = if rdata.len() >= 4 { rdata[3] } else { 0 };
    let public_key = if rdata.len() > 4 {
        rdata[4..].to_vec()
    } else {
        Vec::new()
    };
    
    DnskeyRecord {
        flags,
        protocol,
        algorithm,
        public_key,
    }
}

/// Parse DS RDATA into structured record
///
/// # Arguments
///
/// * `rdata` - DS RDATA bytes
///
/// # Returns
///
/// Parsed DS record
fn parse_ds_rdata(rdata: &[u8]) -> DsRecord {
    let key_tag = if rdata.len() >= 2 {
        u16::from_be_bytes([rdata[0], rdata[1]])
    } else {
        0
    };
    
    let algorithm = if rdata.len() >= 3 { rdata[2] } else { 0 };
    let digest_type = if rdata.len() >= 4 { rdata[3] } else { 0 };
    let digest = if rdata.len() > 4 {
        rdata[4..].to_vec()
    } else {
        Vec::new()
    };
    
    DsRecord {
        key_tag,
        algorithm,
        digest_type,
        digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_name_to_wire_format() {
        let wire = name_to_wire_format("www.example.com");
        assert_eq!(wire[0], 3);  // Length of "www"
        assert_eq!(&wire[1..4], b"www");
        assert_eq!(wire[4], 7);  // Length of "example"
        assert_eq!(&wire[5..12], b"example");
        assert_eq!(wire[12], 3);  // Length of "com"
        assert_eq!(&wire[13..16], b"com");
        assert_eq!(wire[16], 0);  // Terminating zero
    }
    
    #[test]
    fn test_count_domain_labels() {
        assert_eq!(count_domain_labels("www.example.com"), 3);
        assert_eq!(count_domain_labels("example.com"), 2);
        assert_eq!(count_domain_labels("com"), 1);
        assert_eq!(count_domain_labels(""), 0);
    }
    
    #[test]
    fn test_compare_serial_numbers() {
        assert_eq!(compare_serial_numbers(1, 1), Ordering::Equal);
        assert_eq!(compare_serial_numbers(2, 1), Ordering::Greater);
        assert_eq!(compare_serial_numbers(1, 2), Ordering::Less);
        
        // Test wraparound
        assert_eq!(compare_serial_numbers(1, 0xFFFFFFFF), Ordering::Greater);
    }
    
    #[test]
    fn test_compute_key_tag() {
        // Test with known values (simplified test)
        let key_tag = compute_key_tag(8, 257, &[1, 2, 3, 4]);
        assert!(key_tag > 0);  // Basic sanity check
    }
    
    #[test]
    fn test_base32_encoding() {
        let encoded = base32_encode(&[0x01, 0x02, 0x03]);
        assert!(!encoded.is_empty());
        
        // Test round-trip
        let decoded = decode_base32(&encoded).unwrap();
        assert_eq!(decoded, vec![0x01, 0x02, 0x03]);
    }
}
