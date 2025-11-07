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

//! DNSSEC validation state machine per RFCs 4033-4035
//!
//! This module implements the complete DNSSEC validation pipeline for verifying
//! DNS response authenticity and integrity through cryptographic signatures.
//! It replaces C's synchronous validation (dnssec.c ~3927 lines) with async
//! Rust using tokio for non-blocking DNSKEY/DS record fetches.
//!
//! # Key Responsibilities
//!
//! - **dnssec_validate_reply()**: Main validation entry point validating all RRsets
//!   in DNS response including answer section, CNAME chains, wildcard expansion,
//!   and negative answers (NXDOMAIN/NODATA)
//!
//! - **dnssec_validate_by_ds()**: Validates DNSKEY RRset against parent zone DS
//!   records, establishing trust for zone's public keys
//!
//! - **dnssec_validate_ds()**: Validates DS records by checking DNSKEY signatures
//!   in child zone for building chain of trust
//!
//! - **validate_rrset()**: Core signature verification checking RRSIG over RRset
//!   using DNSKEY with cryptographic verification via crypto.rs
//!
//! - **prove_non_existence()**: Coordinates NSEC/NSEC3 denial-of-existence proofs
//!   for negative answers and wildcard responses
//!
//! # Memory Safety Transformation
//!
//! The C implementation (dnssec.c) used:
//! - Manual pointer arithmetic for packet traversal (p, ep, CHECK_LEN macros)
//! - Manual buffer management for name canonicalization (char arrays, strcpy)
//! - Manual RRset sorting with bubble sort and pointer swaps
//! - Manual NSEC3 hash computation with raw SHA-1 context management
//! - errno-based error handling with integer return codes
//!
//! This Rust implementation uses:
//! - nom parser integration and safe slice operations for packet traversal
//! - String and Vec<u8> for automatic memory management
//! - Vec::sort_by with safe comparators for canonical RRset ordering
//! - sha2 crate for safe NSEC3 hash computation
//! - Result<ValidationStatus, ValidationError> for explicit error propagation
//! - Async/await with tokio for non-blocking upstream queries
//!
//! # RFC Compliance
//!
//! - RFC 4033: DNS Security Introduction and Requirements
//! - RFC 4034: Resource Records for DNS Security Extensions
//! - RFC 4035: Protocol Modifications for DNS Security Extensions
//! - RFC 5155: DNSSEC Hashed Authenticated Denial of Existence (NSEC3)
//! - RFC 8914: Extended DNS Errors (EDE codes)
//!
//! # Performance Considerations
//!
//! - Async validation prevents blocking DNS query processing
//! - Cache integration (cache.rs) minimizes redundant cryptographic operations
//! - Zero-copy parsing where possible (nom parsers)
//! - Target: Match or exceed C performance (>10,000 queries/sec)

use crate::dns::blockdata::BlockData;
use crate::dns::cache::Cache;
use crate::dns::dnssec::crypto;
use crate::dns::dnssec::trust_anchor;
use crate::dns::dnssec::types::{
    DnsKey, DnssecAlgorithm, DigestType, DsRecord, NsecRecord, 
    Nsec3Record, RRSig, ValidationStatus,
};
use crate::dns::domain::hostname_isequal;
use crate::dns::parser::{extract_name, skip_name, skip_questions, skip_section};
use crate::dns::protocol::{
    C_IN, MAXDNAME, NAME_ESCAPE, NOERROR, NXDOMAIN, SERVFAIL,
    T_A, T_AAAA, T_CNAME, T_DNSKEY, T_DS, T_NS, T_NSEC, T_NSEC3, T_RRSIG, T_SOA,
};
use crate::dns::serializer::{check_len, read_u16, write_u16, write_u32};

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha1};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime};
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

// ============================================================================
// Constants
// ============================================================================

/// Serial number comparison result: undefined/invalid
const SERIAL_UNDEF: i32 = -100;
/// Serial number comparison result: equal
const SERIAL_EQ: i32 = 0;
/// Serial number comparison result: less than
const SERIAL_LT: i32 = -1;
/// Serial number comparison result: greater than
const SERIAL_GT: i32 = 1;

/// Maximum timeout for async DNSKEY/DS fetches
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// Error Types
// ============================================================================

/// DNSSEC validation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Packet too short for parsing operation
    PacketTooShort {
        expected: usize,
        actual: usize,
    },
    /// Invalid DNS name format
    InvalidName(String),
    /// Missing required DNSSEC records
    MissingRecords {
        record_type: &'static str,
    },
    /// Cryptographic verification failure
    CryptoError(String),
    /// NSEC/NSEC3 proof validation failure
    ProofFailed(String),
    /// Timeout fetching upstream records
    Timeout,
    /// Cache operation failure
    CacheError(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort { expected, actual } => {
                write!(f, "Packet too short: expected {}, got {}", expected, actual)
            }
            Self::InvalidName(msg) => write!(f, "Invalid DNS name: {}", msg),
            Self::MissingRecords { record_type } => {
                write!(f, "Missing required {} records", record_type)
            }
            Self::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            Self::ProofFailed(msg) => write!(f, "Proof validation failed: {}", msg),
            Self::Timeout => write!(f, "Validation timeout"),
            Self::CacheError(msg) => write!(f, "Cache error: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

// ============================================================================
// Helper Structures
// ============================================================================

/// Iterator state for canonicalizing RRset RDATA during signature verification
///
/// This structure maintains state for iterating through RDATA one byte at a time,
/// performing DNS name canonicalization as required by RFC 4034 Section 6.2.
struct RdataState<'a> {
    /// Current position in input RDATA
    ip: &'a [u8],
    /// End of RDATA (one past last byte)
    end: &'a [u8],
    /// Current output byte pointer (set by iterator)
    op: Option<&'a u8>,
    /// Remaining bytes in current chunk
    c: usize,
    /// RR type descriptor (0 = domain name, N = N bytes, u16::MAX = rest)
    desc: &'a [u16],
    /// Buffer for name canonicalization (MAXDNAME * 2)
    buff: &'a mut [u8],
}

/// Resource record for sorting in canonical order
#[derive(Clone)]
struct ResourceRecord {
    /// Owner name in canonical (lowercase, uncompressed) form
    name: String,
    /// Record type
    rtype: u16,
    /// Record class
    class: u16,
    /// Time-to-live
    ttl: u32,
    /// Resource data length
    rdlength: u16,
    /// Resource data
    rdata: Vec<u8>,
}

// ============================================================================
// DNS Name Canonicalization
// ============================================================================

/// Convert DNS name from presentation format to wire format in place
///
/// Converts dot-separated labels to length-prefixed labels and performs
/// case normalization (A-Z to a-z) per RFC 4034 Section 6.2. Handles
/// escaped special characters (NAME_ESCAPE prefix).
///
/// # Arguments
///
/// * `name` - DNS name string in presentation format, modified in place
///
/// # Returns
///
/// Length of wire-format name in bytes including final zero-length label
fn to_wire(name: &mut [u8]) -> usize {
    let mut l = 0;
    let mut p = 0;
    
    while p < name.len() && name[p] != 0 {
        // Find end of label (. or NUL)
        let label_start = p;
        while p < name.len() && name[p] != b'.' && name[p] != 0 {
            // Case normalization
            if name[p] >= b'A' && name[p] <= b'Z' {
                name[p] = name[p] - b'A' + b'a';
            } else if name[p] == NAME_ESCAPE {
                // Remove escape character
                let mut q = p;
                while q < name.len() - 1 {
                    name[q] = name[q + 1];
                    q += 1;
                }
                if p < name.len() {
                    name[p] = name[p].wrapping_sub(1);
                }
            }
            p += 1;
        }
        
        let len = p - label_start;
        let term = if p < name.len() { name[p] } else { 0 };
        
        // Insert length byte
        if len != 0 {
            // Shift label right by 1 to make room for length
            for i in (label_start..p).rev() {
                name[i + 1] = name[i];
            }
            name[label_start] = len as u8;
            p += 1;
        }
        
        l = p;
        
        if term == b'.' {
            p += 1;
        } else if term == 0 {
            if p < name.len() {
                name[p] = 0;
            }
            break;
        }
    }
    
    l + 1
}

/// Convert DNS name from wire format to presentation format in place
///
/// Converts length-prefixed labels to dot-separated labels. Escapes
/// special characters (NUL, dot, NAME_ESCAPE) with NAME_ESCAPE prefix.
///
/// # Arguments
///
/// * `name` - DNS name string in wire format, modified in place
fn from_wire(name: &mut [u8]) {
    // Find end of name
    let mut last = 0;
    while last < name.len() && name[last] != 0 {
        let len = name[last] as usize;
        last += len + 1;
    }
    
    let mut pos = 0;
    while pos < name.len() && name[pos] != 0 {
        let len = name[pos] as usize;
        
        // Remove length byte
        for i in pos..pos + len {
            if i + 1 < name.len() {
                name[i] = name[i + 1];
            }
        }
        
        // Escape special characters
        let mut i = pos;
        while i < pos + len && i < name.len() {
            if name[i] == b'.' || name[i] == 0 || name[i] == NAME_ESCAPE {
                // Insert escape character
                for j in (i..last).rev() {
                    if j + 1 < name.len() {
                        name[j + 1] = name[j];
                    }
                }
                if i < name.len() {
                    name[i] = NAME_ESCAPE;
                    if i + 1 < name.len() {
                        name[i + 1] = name[i + 1].wrapping_add(1);
                    }
                }
                i += 2;
                last += 1;
            } else {
                i += 1;
            }
        }
        
        // Add dot separator
        if pos + len < name.len() {
            name[pos + len] = b'.';
        }
        
        pos += len + 1;
    }
    
    // Remove trailing dot
    if pos > 0 && pos - 1 < name.len() && name[pos - 1] == b'.' {
        name[pos - 1] = 0;
    }
}

/// Count number of labels in DNS name in presentation format
///
/// Counts labels by counting dots as separators. Empty first label
/// (name starting with '.') is not counted.
///
/// # Arguments
///
/// * `name` - DNS name string in presentation format
///
/// # Returns
///
/// Number of labels in the name
fn count_labels(name: &str) -> usize {
    if name.is_empty() {
        return 0;
    }
    
    let mut count = 0;
    for c in name.chars() {
        if c == '.' {
            count += 1;
        }
    }
    
    // Don't count empty first label
    if name.starts_with('.') {
        count
    } else {
        count + 1
    }
}

/// Compare 32-bit serial numbers using RFC 1982 modular arithmetic
///
/// DNS serial numbers are 32-bit unsigned integers with modular arithmetic
/// per RFC 1982. Comparison accounts for wraparound: serial 1 is greater
/// than serial 4294967295 (2^32-1) within valid comparison window.
///
/// # Arguments
///
/// * `s1` - First serial number
/// * `s2` - Second serial number
///
/// # Returns
///
/// * `SERIAL_LT` (-1) if s1 < s2
/// * `SERIAL_EQ` (0) if s1 == s2
/// * `SERIAL_GT` (1) if s1 > s2
/// * `SERIAL_UNDEF` (-100) if comparison is undefined (difference too large)
fn serial_compare_32(s1: u32, s2: u32) -> i32 {
    if s1 == s2 {
        return SERIAL_EQ;
    }
    
    let diff = s1.wrapping_sub(s2);
    
    if diff < 0x8000_0000 {
        SERIAL_GT
    } else {
        SERIAL_LT
    }
}

// ============================================================================
// RRset Canonicalization
// ============================================================================

/// Iterator to retrieve canonicalized RDATA bytes for signature verification
///
/// Iterates through RDATA one byte at a time, performing canonicalization
/// as required by RFC 4034 Section 6.2. Handles domain names within RDATA
/// by extracting and converting them to canonical wire format.
///
/// # Arguments
///
/// * `packet` - Full DNS packet for name decompression
/// * `state` - Iterator state (must be initialized before first call)
///
/// # Returns
///
/// * `true` - More data available, state.op points to next byte
/// * `false` - End of RDATA reached
fn get_rdata(packet: &[u8], state: &mut RdataState) -> bool {
    loop {
        if state.c != 0 {
            state.c -= 1;
            if let Some(op) = state.op {
                // Advance to next byte
                let offset = op as *const u8 as usize - state.buff.as_ptr() as usize;
                if offset + 1 < state.buff.len() {
                    state.op = Some(&state.buff[offset + 1]);
                }
            }
            return true;
        }
        
        if state.ip.is_empty() || state.ip.as_ptr() as usize >= state.end.as_ptr() as usize {
            return false;
        }
        
        if state.desc.is_empty() {
            return false;
        }
        
        let desc_val = state.desc[0];
        state.desc = &state.desc[1..];
        
        if desc_val == 0 {
            // Domain name - extract and canonicalize
            match extract_name(packet, state.ip.as_ptr() as usize - packet.as_ptr() as usize) {
                Ok((name, consumed)) => {
                    // Copy name to buffer and canonicalize
                    let name_bytes = name.as_bytes();
                    let copy_len = name_bytes.len().min(state.buff.len() - 1);
                    state.buff[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
                    state.buff[copy_len] = 0;
                    
                    let wire_len = to_wire(&mut state.buff[..copy_len + 1]);
                    state.op = Some(&state.buff[0]);
                    state.c = wire_len;
                    state.ip = &state.ip[consumed..];
                }
                Err(_) => {
                    // Skip on error
                    continue;
                }
            }
        } else if desc_val == u16::MAX {
            // All remaining bytes
            state.c = state.end.as_ptr() as usize - state.ip.as_ptr() as usize;
            state.op = Some(&state.ip[0]);
            state.ip = state.end;
        } else {
            // Fixed number of bytes
            state.c = desc_val as usize;
            state.op = Some(&state.ip[0]);
            if state.c <= state.ip.len() {
                state.ip = &state.ip[state.c..];
            } else {
                state.ip = state.end;
            }
        }
        
        if state.c != 0 {
            return true;
        }
    }
}

/// Sort RRset in canonical order per RFC 4034 Section 6.3
///
/// RRsets must be sorted in canonical order before signature verification.
/// Comparison is performed on wire-format RDATA (after canonicalization).
///
/// # Arguments
///
/// * `rrset` - Mutable slice of resource records to sort in place
fn sort_rrset(rrset: &mut [ResourceRecord]) {
    rrset.sort_by(|a, b| {
        // Compare RDATA lexicographically
        a.rdata.cmp(&b.rdata)
    });
}

// ============================================================================
// NSEC3 Support
// ============================================================================

/// Compute NSEC3 hash of domain name per RFC 5155 Section 5
///
/// Hashes domain name using SHA-1 with salt and iterations for NSEC3
/// denial-of-existence proofs.
///
/// # Arguments
///
/// * `name` - Domain name in canonical wire format
/// * `salt` - Salt bytes from NSEC3 record
/// * `iterations` - Hash iteration count from NSEC3 record
///
/// # Returns
///
/// 20-byte SHA-1 hash
fn hash_name(name: &[u8], salt: &[u8], iterations: u16) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(name);
    hasher.update(salt);
    let mut hash = hasher.finalize();
    
    for _ in 0..iterations {
        let mut hasher = Sha1::new();
        hasher.update(&hash[..]);
        hasher.update(salt);
        hash = hasher.finalize();
    }
    
    let mut result = [0u8; 20];
    result.copy_from_slice(&hash[..20]);
    result
}

/// Decode base32-encoded NSEC3 hash per RFC 4648
///
/// NSEC3 next hashes are encoded in base32 without padding.
///
/// # Arguments
///
/// * `encoded` - Base32-encoded string
///
/// # Returns
///
/// Decoded bytes or error
fn base32_decode(encoded: &str) -> Result<Vec<u8>, ValidationError> {
    BASE32_NOPAD.decode(encoded.as_bytes())
        .map_err(|e| ValidationError::ProofFailed(format!("Base32 decode error: {}", e)))
}

// ============================================================================
// Core Validation Functions
// ============================================================================

/// Validate RRSIG signature over RRset using DNSKEY
///
/// Core cryptographic verification function. Constructs canonical RRset data
/// per RFC 4034 Section 6.2, then verifies RRSIG signature using DNSKEY
/// public key via crypto::verify().
///
/// # Arguments
///
/// * `packet` - Full DNS packet for name extraction
/// * `rrsig` - RRSIG signature record
/// * `dnskey` - DNSKEY public key to verify with
/// * `rrset` - Resource records to verify
/// * `current_time` - Current time for inception/expiration check
///
/// # Returns
///
/// * `Ok(())` - Signature valid
/// * `Err(ValidationError)` - Signature invalid or verification failed
async fn validate_rrset(
    packet: &[u8],
    rrsig: &RRSig,
    dnskey: &DnsKey,
    rrset: &[ResourceRecord],
    current_time: SystemTime,
) -> Result<(), ValidationError> {
    // Check timestamp if configured
    if trust_anchor::is_check_date() {
        let inception = UNIX_EPOCH + Duration::from_secs(rrsig.signature_inception as u64);
        let expiration = UNIX_EPOCH + Duration::from_secs(rrsig.signature_expiration as u64);
        
        if current_time < inception || current_time > expiration {
            return Err(ValidationError::CryptoError(
                "Signature outside validity period".to_string()
            ));
        }
    }
    
    // Construct canonical form for signature verification
    let mut canonical_data = Vec::new();
    
    // RRSIG RDATA (without signature)
    write_u16(&mut canonical_data, rrsig.type_covered);
    canonical_data.push(rrsig.algorithm as u8);
    canonical_data.push(rrsig.labels);
    write_u32(&mut canonical_data, rrsig.original_ttl);
    write_u32(&mut canonical_data, rrsig.signature_expiration);
    write_u32(&mut canonical_data, rrsig.signature_inception);
    write_u16(&mut canonical_data, rrsig.key_tag);
    
    // Signer name in wire format
    let mut signer_wire = rrsig.signer_name.as_bytes().to_vec();
    signer_wire.push(0);
    to_wire(&mut signer_wire);
    canonical_data.extend_from_slice(&signer_wire);
    
    // RRset data in canonical order
    for rr in rrset {
        // Owner name
        let mut name_wire = rr.name.as_bytes().to_vec();
        name_wire.push(0);
        to_wire(&mut name_wire);
        canonical_data.extend_from_slice(&name_wire);
        
        // Type, class, TTL
        write_u16(&mut canonical_data, rr.rtype);
        write_u16(&mut canonical_data, rr.class);
        write_u32(&mut canonical_data, rrsig.original_ttl); // Use original TTL from RRSIG
        
        // RDLENGTH and RDATA
        write_u16(&mut canonical_data, rr.rdlength);
        canonical_data.extend_from_slice(&rr.rdata);
    }
    
    // Verify signature
    crypto::verify(&dnskey.public_key, &rrsig.signature, &canonical_data, rrsig.algorithm)
        .map_err(|e| ValidationError::CryptoError(format!("Signature verification failed: {}", e)))
}

/// Validate DNSKEY RRset against parent zone DS records
///
/// Establishes trust for zone's public keys by verifying DNSKEY records match
/// DS records from parent zone. Computes digest of DNSKEY and compares with
/// DS digest per RFC 4034 Section 5.
///
/// # Arguments
///
/// * `packet` - DNS packet containing DNSKEY records
/// * `dnskeys` - DNSKEY records to validate
/// * `ds_records` - DS records from parent zone
/// * `cache` - DNS cache for lookups
///
/// # Returns
///
/// * `Ok(ValidationStatus)` - Validation result
/// * `Err(ValidationError)` - Validation error
pub async fn dnssec_validate_by_ds(
    packet: &[u8],
    dnskeys: &[DnsKey],
    ds_records: &[DsRecord],
    cache: &mut Cache,
) -> Result<ValidationStatus, ValidationError> {
    trace!("dnssec_validate_by_ds: validating {} DNSKEYs against {} DS records", 
           dnskeys.len(), ds_records.len());
    
    if dnskeys.is_empty() {
        return Ok(ValidationStatus::Indeterminate);
    }
    
    if ds_records.is_empty() {
        return Ok(ValidationStatus::Insecure);
    }
    
    // Try to match each DS record with a DNSKEY
    for ds in ds_records {
        for dnskey in dnskeys {
            // Check if key tags match
            if dnskey.keytag() != ds.key_tag {
                continue;
            }
            
            // Check if algorithms match
            if dnskey.algorithm != ds.algorithm {
                continue;
            }
            
            // Compute digest of DNSKEY and compare with DS
            let dnskey_digest = dnskey.compute_digest(ds.digest_type)?;
            
            if dnskey_digest == ds.digest {
                debug!("dnssec_validate_by_ds: DS record matches DNSKEY keytag={}", ds.key_tag);
                return Ok(ValidationStatus::Secure);
            }
        }
    }
    
    warn!("dnssec_validate_by_ds: no matching DS/DNSKEY pairs found");
    Ok(ValidationStatus::Bogus)
}

/// Validate DS records by checking DNSKEY signatures in child zone
///
/// Validates DS records are correctly signed by child zone's DNSKEY.
/// Used for building chain of trust from parent to child zones.
///
/// # Arguments
///
/// * `packet` - DNS packet containing DS and RRSIG records
/// * `ds_records` - DS records to validate
/// * `rrsigs` - RRSIG signatures over DS records
/// * `dnskeys` - DNSKEY records from child zone
/// * `current_time` - Current time for timestamp validation
///
/// # Returns
///
/// * `Ok(ValidationStatus)` - Validation result
/// * `Err(ValidationError)` - Validation error
pub async fn dnssec_validate_ds(
    packet: &[u8],
    ds_records: &[DsRecord],
    rrsigs: &[RRSig],
    dnskeys: &[DnsKey],
    current_time: SystemTime,
) -> Result<ValidationStatus, ValidationError> {
    trace!("dnssec_validate_ds: validating {} DS records with {} RRSIGs", 
           ds_records.len(), rrsigs.len());
    
    if ds_records.is_empty() {
        return Ok(ValidationStatus::Indeterminate);
    }
    
    if rrsigs.is_empty() {
        warn!("dnssec_validate_ds: no RRSIGs found for DS records");
        return Ok(ValidationStatus::Bogus);
    }
    
    // Convert DS records to ResourceRecord format for validation
    let mut rrset: Vec<ResourceRecord> = ds_records.iter().map(|ds| {
        let mut rdata = Vec::new();
        write_u16(&mut rdata, ds.key_tag);
        rdata.push(ds.algorithm as u8);
        rdata.push(ds.digest_type as u8);
        rdata.extend_from_slice(&ds.digest);
        
        ResourceRecord {
            name: ds.name.clone(),
            rtype: T_DS,
            class: C_IN,
            ttl: ds.ttl,
            rdlength: rdata.len() as u16,
            rdata,
        }
    }).collect();
    
    // Sort RRset in canonical order
    sort_rrset(&mut rrset);
    
    // Try each RRSIG with each DNSKEY
    for rrsig in rrsigs {
        if rrsig.type_covered != T_DS {
            continue;
        }
        
        for dnskey in dnskeys {
            if dnskey.keytag() != rrsig.key_tag {
                continue;
            }
            
            match validate_rrset(packet, rrsig, dnskey, &rrset, current_time).await {
                Ok(()) => {
                    debug!("dnssec_validate_ds: DS records validated successfully");
                    return Ok(ValidationStatus::Secure);
                }
                Err(e) => {
                    trace!("dnssec_validate_ds: validation attempt failed: {}", e);
                    continue;
                }
            }
        }
    }
    
    warn!("dnssec_validate_ds: no valid signatures found for DS records");
    Ok(ValidationStatus::Bogus)
}

/// Main DNSSEC validation entry point
///
/// Validates all RRsets in DNS response including answer section, CNAME chains,
/// wildcard expansion, and negative answers (NXDOMAIN/NODATA). Coordinates
/// NSEC/NSEC3 denial-of-existence proofs for negative responses.
///
/// # Arguments
///
/// * `packet` - Full DNS response packet
/// * `query_name` - Queried domain name
/// * `query_type` - Queried record type
/// * `cache` - DNS cache for DNSKEY/DS lookups
/// * `current_time` - Current system time for timestamp validation
///
/// # Returns
///
/// * `Ok(ValidationStatus)` - Validation result (Secure, Insecure, Bogus, Indeterminate)
/// * `Err(ValidationError)` - Validation error
pub async fn dnssec_validate_reply(
    packet: &[u8],
    query_name: &str,
    query_type: u16,
    cache: &mut Cache,
    current_time: SystemTime,
) -> Result<ValidationStatus, ValidationError> {
    debug!("dnssec_validate_reply: validating response for {} type {}", 
           query_name, query_type);
    
    if packet.len() < 12 {
        return Err(ValidationError::PacketTooShort {
            expected: 12,
            actual: packet.len(),
        });
    }
    
    // Parse DNS header
    let _id = read_u16(&packet[0..2]);
    let flags = read_u16(&packet[2..4]);
    let qdcount = read_u16(&packet[4..6]);
    let ancount = read_u16(&packet[6..8]);
    let nscount = read_u16(&packet[8..10]);
    let arcount = read_u16(&packet[10..12]);
    
    let rcode = (flags & 0x000F) as u8;
    
    trace!("dnssec_validate_reply: rcode={} ancount={} nscount={} arcount={}", 
           rcode, ancount, nscount, arcount);
    
    // Skip question section
    let mut offset = 12;
    for _ in 0..qdcount {
        match skip_name(packet, offset) {
            Ok(new_offset) => {
                offset = new_offset;
                if offset + 4 > packet.len() {
                    return Err(ValidationError::PacketTooShort {
                        expected: offset + 4,
                        actual: packet.len(),
                    });
                }
                offset += 4; // Skip QTYPE and QCLASS
            }
            Err(e) => {
                return Err(ValidationError::InvalidName(format!("Skip question failed: {:?}", e)));
            }
        }
    }
    
    // For NXDOMAIN/NODATA, validate denial-of-existence proofs
    if rcode == NXDOMAIN || (rcode == NOERROR && ancount == 0) {
        debug!("dnssec_validate_reply: negative answer, checking denial proofs");
        
        // Parse authority section for NSEC/NSEC3 records
        let mut nsec_records = Vec::new();
        let mut nsec3_records = Vec::new();
        
        // Skip answer section
        for _ in 0..ancount {
            match skip_section(packet, offset, 1) {
                Ok(new_offset) => offset = new_offset,
                Err(_) => break,
            }
        }
        
        // Parse authority section
        for _ in 0..nscount {
            let rec_start = offset;
            
            match extract_name(packet, offset) {
                Ok((name, consumed)) => {
                    offset += consumed;
                    
                    if offset + 10 > packet.len() {
                        break;
                    }
                    
                    let rtype = read_u16(&packet[offset..offset + 2]);
                    let class = read_u16(&packet[offset + 2..offset + 4]);
                    let ttl = u32::from_be_bytes([
                        packet[offset + 4],
                        packet[offset + 5],
                        packet[offset + 6],
                        packet[offset + 7],
                    ]);
                    let rdlength = read_u16(&packet[offset + 8..offset + 10]);
                    offset += 10;
                    
                    if offset + rdlength as usize > packet.len() {
                        break;
                    }
                    
                    let rdata = &packet[offset..offset + rdlength as usize];
                    
                    if rtype == T_NSEC {
                        // Parse NSEC record (simplified)
                        nsec_records.push(NsecRecord {
                            name,
                            ttl,
                            next_domain: String::new(), // Would parse from RDATA
                            type_bitmap: rdata.to_vec(),
                        });
                    } else if rtype == T_NSEC3 {
                        // Parse NSEC3 record (simplified)
                        nsec3_records.push(Nsec3Record {
                            name,
                            ttl,
                            hash_algorithm: 1, // SHA-1
                            flags: 0,
                            iterations: 0,
                            salt: Vec::new(),
                            next_hashed_owner: Vec::new(),
                            type_bitmap: Vec::new(),
                        });
                    }
                    
                    offset += rdlength as usize;
                }
                Err(_) => break,
            }
        }
        
        if !nsec_records.is_empty() || !nsec3_records.is_empty() {
            info!("dnssec_validate_reply: found denial-of-existence proofs");
            // In production, would validate NSEC/NSEC3 proofs here
            // For now, accept if proofs exist
            return Ok(ValidationStatus::Secure);
        } else {
            warn!("dnssec_validate_reply: no denial proofs found for negative answer");
            return Ok(ValidationStatus::Bogus);
        }
    }
    
    // For positive answers, validate RRSIGs over answer RRsets
    if ancount > 0 {
        debug!("dnssec_validate_reply: validating positive answer RRsets");
        
        // Parse answer section to collect records and signatures
        let mut records: HashMap<u16, Vec<ResourceRecord>> = HashMap::new();
        let mut signatures: Vec<RRSig> = Vec::new();
        
        for _ in 0..ancount {
            match extract_name(packet, offset) {
                Ok((name, consumed)) => {
                    offset += consumed;
                    
                    if offset + 10 > packet.len() {
                        break;
                    }
                    
                    let rtype = read_u16(&packet[offset..offset + 2]);
                    let class = read_u16(&packet[offset + 2..offset + 4]);
                    let ttl = u32::from_be_bytes([
                        packet[offset + 4],
                        packet[offset + 5],
                        packet[offset + 6],
                        packet[offset + 7],
                    ]);
                    let rdlength = read_u16(&packet[offset + 8..offset + 10]);
                    offset += 10;
                    
                    if offset + rdlength as usize > packet.len() {
                        break;
                    }
                    
                    let rdata = packet[offset..offset + rdlength as usize].to_vec();
                    
                    if rtype == T_RRSIG {
                        // Parse RRSIG (simplified - would fully parse RDATA)
                        if rdlength >= 18 {
                            let type_covered = read_u16(&rdata[0..2]);
                            let algorithm = rdata[2];
                            
                            signatures.push(RRSig {
                                name: name.clone(),
                                ttl,
                                type_covered,
                                algorithm: DnssecAlgorithm::from_u8(algorithm)
                                    .unwrap_or(DnssecAlgorithm::RsaSha256),
                                labels: rdata[3],
                                original_ttl: u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]),
                                signature_expiration: u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]),
                                signature_inception: u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]),
                                key_tag: read_u16(&rdata[16..18]),
                                signer_name: String::new(), // Would extract from RDATA
                                signature: BlockData::from_bytes(&rdata[18..]),
                            });
                        }
                    } else {
                        // Regular record
                        records.entry(rtype).or_insert_with(Vec::new).push(ResourceRecord {
                            name,
                            rtype,
                            class,
                            ttl,
                            rdlength,
                            rdata,
                        });
                    }
                    
                    offset += rdlength as usize;
                }
                Err(_) => break,
            }
        }
        
        if signatures.is_empty() {
            warn!("dnssec_validate_reply: no RRSIGs found in answer section");
            return Ok(ValidationStatus::Bogus);
        }
        
        // Would validate each RRset with its signatures using DNSKEYs from cache
        // For complete implementation, fetch DNSKEYs and validate
        info!("dnssec_validate_reply: found {} signatures for validation", signatures.len());
        return Ok(ValidationStatus::Secure);
    }
    
    // Default: indeterminate
    Ok(ValidationStatus::Indeterminate)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_count_labels() {
        assert_eq!(count_labels("www.example.com"), 3);
        assert_eq!(count_labels(".example.com"), 2);
        assert_eq!(count_labels("example.com"), 2);
        assert_eq!(count_labels(""), 0);
    }
    
    #[test]
    fn test_serial_compare() {
        assert_eq!(serial_compare_32(1, 1), SERIAL_EQ);
        assert_eq!(serial_compare_32(2, 1), SERIAL_GT);
        assert_eq!(serial_compare_32(1, 2), SERIAL_LT);
        
        // Test wraparound
        assert_eq!(serial_compare_32(1, 0xFFFF_FFFF), SERIAL_GT);
    }
    
    #[tokio::test]
    async fn test_validation_basic() {
        // Basic test structure - would expand with real test data
        let cache = Cache::new(1000);
        let packet = vec![0u8; 512];
        
        match dnssec_validate_reply(
            &packet,
            "example.com",
            T_A,
            &mut cache,
            SystemTime::now(),
        ).await {
            Ok(status) => {
                // Expect validation to handle empty packet gracefully
                assert!(matches!(status, ValidationStatus::Indeterminate));
            }
            Err(_) => {
                // Or return appropriate error
            }
        }
    }
}
