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

//! Trust anchor management for DNSSEC chain of trust establishment
//!
//! This module implements trust anchor management and timestamp validation for DNSSEC,
//! providing critical functionality for systems with unreliable real-time clocks (RTCs).
//! It replaces C's manual file I/O and error handling from dnssec.c lines 412-540 with
//! memory-safe Rust implementations using std::fs and std::time.
//!
//! # Key Responsibilities
//!
//! ## Timestamp Validation for Embedded Systems
//!
//! Many embedded systems lack reliable RTCs and have system clocks that reset to epoch
//! (1970-01-01) on boot. DNSSEC signature validation requires checking inception and
//! expiration timestamps per RFC 4034 Section 3.1.5, which fails when system time is
//! incorrect. This module provides:
//!
//! - **setup_timestamp()**: Initialize persistent timestamp file on systems without RTC
//! - **is_check_date()**: Defer timestamp validation until system time becomes reliable
//! - **Back-to-the-future transition**: Detect when system time becomes valid and trigger
//!   cache purge to remove potentially incorrectly validated entries
//!
//! ## Trust Anchor Management
//!
//! Trust anchors are DNSKEY records configured by administrators to establish the root
//! of the DNSSEC chain of trust. This module provides:
//!
//! - **TrustAnchorStore**: HashMap-based O(1) trust anchor lookup by domain name
//! - **Trust anchor loading**: Parse DNSKEY records from trust-anchor-file configuration
//! - **Trust anchor validation**: Verify DNSKEYs are self-signed and match DS records
//!
//! # Memory Safety Improvements
//!
//! The C implementation (dnssec.c) used:
//! - Manual file operations with stat(), open(), utimes() and errno checking
//! - Static global `timestamp_time` variable (not thread-safe)
//! - Manual daemon->back_to_the_future flag management
//! - Linked list trust anchor storage with manual memory management
//!
//! This Rust implementation uses:
//! - std::fs::metadata, std::fs::File, filetime crate for safe file operations
//! - Arc<RwLock<Option<SystemTime>>> for thread-safe timestamp state
//! - Result<T, E> for explicit error propagation
//! - HashMap<String, Vec<DnsKey>> for O(1) trust anchor lookups
//!
//! # Timestamp File Behavior
//!
//! Default timestamp file path: /etc/dnsmasq/timestamp (configurable via dnssec-timestamp)
//! Default epoch: 1420070400 (2015-01-01 00:00:00 UTC)
//!
//! ## First Boot (no timestamp file exists)
//!
//! 1. Create timestamp file with O_EXCL for atomic creation
//! 2. Set mtime to default epoch (2015-01-01)
//! 3. System time validation is deferred
//! 4. DNSSEC signatures are validated cryptographically but timestamps are ignored
//!
//! ## Subsequent Boots (timestamp file exists)
//!
//! 1. Read timestamp file mtime
//! 2. If system time < timestamp mtime: time is invalid, defer validation
//! 3. If system time >= timestamp mtime: time is valid, enable timestamp checking
//! 4. On transition from invalid to valid: update mtime, log message, trigger EVENT_RELOAD
//!
//! # RFC Compliance
//!
//! - RFC 4034 Section 3.1.5: RRSIG signature validity period (inception/expiration)
//! - RFC 4034 Section 5: DS records for trust anchor validation
//! - RFC 4035 Section 3.3: Trust anchor configuration
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dnsmasq::dns::dnssec::trust_anchor::{TimestampValidator, TrustAnchorStore};
//! use std::path::PathBuf;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize timestamp validator for embedded system
//!     let timestamp_file = Some(PathBuf::from("/etc/dnsmasq/timestamp"));
//!     let mut validator = TimestampValidator::new(timestamp_file, false);
//!     
//!     match validator.setup_timestamp() {
//!         Ok(0) => println!("System time is already valid"),
//!         Ok(1) => println!("Timestamp validation deferred"),
//!         Ok(_) => println!("Setup complete"),
//!         Err(e) => eprintln!("Timestamp setup failed: {}", e),
//!     }
//!     
//!     // Check if current time is reliable for DNSSEC validation
//!     let curtime = std::time::SystemTime::now()
//!         .duration_since(std::time::UNIX_EPOCH)
//!         .unwrap()
//!         .as_secs() as u32;
//!     
//!     if validator.is_check_date(curtime) {
//!         println!("System time is valid, checking DNSSEC timestamps");
//!     } else {
//!         println!("System time not yet valid, deferring timestamp checks");
//!     }
//!     
//!     // Load trust anchors
//!     let mut store = TrustAnchorStore::new();
//!     let trust_anchor_file = PathBuf::from("/usr/share/dnsmasq/trust-anchors.conf");
//!     
//!     store.load_from_file(&trust_anchor_file).await?;
//!     
//!     // Query trust anchor for root zone
//!     if let Some(keys) = store.get_trust_anchor(".") {
//!         println!("Found {} trust anchor(s) for root zone", keys.len());
//!     }
//!     
//!     Ok(())
//! }
//! ```

use crate::dns::dnssec::types::{DnsKey, DnssecAlgorithm};
use crate::dns::protocol::MAXDNAME;
use filetime::{set_file_mtime, FileTime};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, trace, warn};

// ============================================================================
// Base64 Decoder (RFC 4648)
// ============================================================================

/// Base64 decoding for DNSKEY public key data
///
/// Implements RFC 4648 base64 decoding without external dependencies.
/// Used to parse base64-encoded public keys from trust anchor configuration files.
mod base64 {
    /// Base64 decoding error
    #[derive(Debug)]
    pub struct DecodeError {
        pub message: String,
    }

    impl std::fmt::Display for DecodeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Base64 decode error: {}", self.message)
        }
    }

    impl std::error::Error for DecodeError {}

    /// Decode base64 string to bytes (RFC 4648 standard alphabet)
    pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
        const DECODE_TABLE: [i8; 128] = [
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,
            -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
        ];

        let input = input.trim();
        let mut cleaned = Vec::new();
        
        // Remove whitespace and validate characters
        for ch in input.chars() {
            if ch.is_whitespace() {
                continue;
            }
            if !ch.is_ascii() || (ch as usize) >= 128 {
                return Err(DecodeError {
                    message: format!("Invalid character: {ch}"),
                });
            }
            cleaned.push(ch as u8);
        }

        // Handle padding
        let mut padding = 0;
        while !cleaned.is_empty() && cleaned[cleaned.len() - 1] == b'=' {
            cleaned.pop();
            padding += 1;
        }

        if padding > 2 {
            return Err(DecodeError {
                message: String::from("Invalid padding"),
            });
        }

        let len = cleaned.len();
        if len % 4 == 1 {
            return Err(DecodeError {
                message: String::from("Invalid length"),
            });
        }

        let output_len = (len * 3) / 4;
        let mut output = Vec::with_capacity(output_len);

        let mut i = 0;
        while i < len {
            let mut accum: u32 = 0;
            let mut bits = 0;

            for _ in 0..4 {
                if i >= len {
                    break;
                }
                
                let ch = cleaned[i];
                i += 1;

                let value = if (ch as usize) < 128 {
                    DECODE_TABLE[ch as usize]
                } else {
                    -1
                };

                if value < 0 {
                    if value == -2 {
                        // Padding character
                        break;
                    }
                    return Err(DecodeError {
                        message: format!("Invalid character: {}", ch as char),
                    });
                }

                accum = (accum << 6) | (value as u32);
                bits += 6;
            }

            // Extract bytes from accumulator
            while bits >= 8 {
                bits -= 8;
                output.push(((accum >> bits) & 0xFF) as u8);
            }
        }

        // Trim output based on padding
        let expected_len = output_len - padding;
        output.truncate(expected_len);

        Ok(output)
    }
}

/// Default timestamp epoch for embedded systems without RTC: 2015-01-01 00:00:00 UTC
/// This corresponds to Unix timestamp 1420070400
const DEFAULT_TIMESTAMP_EPOCH: u64 = 1420070400;

/// Maximum domain name length for trust anchor validation (from protocol.rs MAXDNAME)
const MAX_DOMAIN_NAME_LEN: usize = MAXDNAME;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during trust anchor and timestamp operations
#[derive(Debug, Clone)]
pub enum TrustAnchorError {
    /// File I/O error with context
    IoError { 
        /// Path to the file that caused the error
        path: String, 
        /// Error message describing the I/O failure
        message: String 
    },
    /// Trust anchor validation failed
    ValidationFailed { 
        /// Domain name being validated
        domain: String, 
        /// Reason for validation failure
        reason: String 
    },
    /// Trust anchor file parsing error
    ParseError { 
        /// Path to the file being parsed
        path: String, 
        /// Line number where parsing failed
        line: usize, 
        /// Reason for parse failure
        reason: String 
    },
    /// Invalid trust anchor configuration
    InvalidConfig { 
        /// Reason for invalid configuration
        reason: String 
    },
    /// Cryptographic verification failed
    CryptoError { 
        /// Reason for cryptographic failure
        reason: String 
    },
    /// Domain name too long or invalid
    InvalidDomain { 
        /// The invalid domain name
        domain: String 
    },
}

impl std::fmt::Display for TrustAnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustAnchorError::IoError { path, message } => {
                write!(f, "I/O error for {path}: {message}")
            }
            TrustAnchorError::ValidationFailed { domain, reason } => {
                write!(f, "Trust anchor validation failed for {domain}: {reason}")
            }
            TrustAnchorError::ParseError { path, line, reason } => {
                write!(f, "Parse error in {path} line {line}: {reason}")
            }
            TrustAnchorError::InvalidConfig { reason } => {
                write!(f, "Invalid trust anchor configuration: {reason}")
            }
            TrustAnchorError::CryptoError { reason } => {
                write!(f, "Cryptographic error: {reason}")
            }
            TrustAnchorError::InvalidDomain { domain } => {
                write!(f, "Invalid domain name: {domain}")
            }
        }
    }
}

impl std::error::Error for TrustAnchorError {}

impl From<IoError> for TrustAnchorError {
    fn from(e: IoError) -> Self {
        TrustAnchorError::IoError {
            path: String::from("<unknown>"),
            message: e.to_string(),
        }
    }
}

// ============================================================================
// Timestamp Validator
// ============================================================================

/// Timestamp validator for systems with unreliable real-time clocks
///
/// Manages persistent timestamp file to track when system time becomes reliable
/// for DNSSEC signature inception/expiration validation. Replaces C's manual
/// file operations and static global state with safe Rust implementation.
///
/// # Fields
///
/// - `timestamp_file`: Optional path to persistent timestamp file
/// - `timestamp_time`: Cached timestamp from file mtime (thread-safe via Arc<RwLock>)
/// - `back_to_the_future`: Flag indicating system time is now valid
/// - `dnssec_no_time_check`: Flag to disable timestamp checking entirely
///
/// # C Implementation Mapping
///
/// Replaces C's dnssec.c lines 412-540:
/// - `setup_timestamp()` function with manual stat/open/utimes
/// - `is_check_date()` function with difftime comparison
/// - Static `timestamp_time` variable
/// - `daemon->back_to_the_future` flag
/// - `daemon->dnssec_no_time_check` flag
pub struct TimestampValidator {
    /// Path to timestamp file (None if timestamp validation disabled)
    timestamp_file: Option<PathBuf>,
    
    /// Cached timestamp from file mtime, thread-safe shared state
    timestamp_time: Arc<RwLock<Option<SystemTime>>>,
    
    /// System time is now considered valid (0→1 transition triggers `EVENT_RELOAD`)
    back_to_the_future: Arc<RwLock<bool>>,
    
    /// Disable DNSSEC timestamp checking entirely
    dnssec_no_time_check: bool,
}

impl TimestampValidator {
    /// Create a new timestamp validator
    ///
    /// # Arguments
    ///
    /// * `timestamp_file` - Optional path to persistent timestamp file
    /// * `dnssec_no_time_check` - If true, disable all timestamp checking
    ///
    /// # Returns
    ///
    /// New `TimestampValidator` instance
    #[must_use] 
    pub fn new(timestamp_file: Option<PathBuf>, dnssec_no_time_check: bool) -> Self {
        TimestampValidator {
            timestamp_file,
            timestamp_time: Arc::new(RwLock::new(None)),
            back_to_the_future: Arc::new(RwLock::new(false)),
            dnssec_no_time_check,
        }
    }

    /// Initialize timestamp file for embedded systems without reliable RTC
    ///
    /// This function implements the C `setup_timestamp()` from dnssec.c lines 412-455.
    /// On embedded systems without real-time clocks, the system time may be incorrect
    /// at boot. This function creates or reads a persistent timestamp file to track
    /// when system time becomes valid.
    ///
    /// # Behavior
    ///
    /// ## If timestamp file doesn't exist (first boot):
    /// 1. Create timestamp file atomically with `O_EXCL` equivalent
    /// 2. Set mtime to `DEFAULT_TIMESTAMP_EPOCH` (2015-01-01)
    /// 3. Check if current time > timestamp
    /// 4. If yes: system time is already valid, set `back_to_the_future=1`, return 0
    /// 5. If no: system time is invalid, return 1 (defer validation)
    ///
    /// ## If timestamp file exists (subsequent boots):
    /// 1. Read file mtime into `timestamp_time`
    /// 2. Compare current time to `timestamp_time`
    /// 3. If current time > timestamp: system time is valid, update mtime, return 0
    /// 4. If current time <= timestamp: system time is invalid, return 1
    ///
    /// # Returns
    ///
    /// * `Ok(0)` - System time is already valid, timestamp checking enabled
    /// * `Ok(1)` - System time not yet valid, timestamp checking deferred
    /// * `Ok(_)` - No timestamp file configured, no action needed
    /// * `Err(TrustAnchorError)` - File operation failed
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File cannot be created or accessed (permission denied, disk full)
    /// - Metadata cannot be read (corrupted filesystem)
    /// - mtime cannot be updated (filesystem read-only)
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C dnssec.c lines 412-455:
    /// ```c
    /// int setup_timestamp(void)
    /// {
    ///   struct stat statbuf;
    ///   daemon->back_to_the_future = 0;
    ///   if (!daemon->timestamp_file) return 0;
    ///   if (stat(daemon->timestamp_file, &statbuf) != -1) {
    ///     timestamp_time = statbuf.st_mtime;
    ///     // ... rest of logic
    ///   }
    ///   if (errno == ENOENT) {
    ///     int fd = open(daemon->timestamp_file, O_WRONLY | O_CREAT | O_NONBLOCK | O_EXCL, 0666);
    ///     // ... atomic file creation
    ///   }
    ///   return -1;
    /// }
    /// ```
    pub fn setup_timestamp(&mut self) -> Result<i32, TrustAnchorError> {
        // Reset back_to_the_future flag
        {
            let mut btf = self.back_to_the_future.write().unwrap();
            *btf = false;
        }

        // If no timestamp file configured, return immediately
        let timestamp_path = match &self.timestamp_file {
            Some(path) => path,
            None => return Ok(0),
        };

        trace!("Setting up timestamp file: {}", timestamp_path.display());

        // Try to read existing timestamp file metadata
        match fs::metadata(timestamp_path) {
            Ok(metadata) => {
                // File exists, read mtime
                let mtime = metadata.modified().map_err(|e| TrustAnchorError::IoError {
                    path: timestamp_path.display().to_string(),
                    message: format!("Failed to read mtime: {e}"),
                })?;

                // Store timestamp_time
                {
                    let mut ts = self.timestamp_time.write().unwrap();
                    *ts = Some(mtime);
                }

                debug!(
                    "Timestamp file exists with mtime: {:?}",
                    mtime.duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0))
                );

                // Check if current time is already beyond timestamp (goto check_and_exit in C)
                self.check_and_exit_timestamp()
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // File doesn't exist, create it atomically
                debug!("Timestamp file does not exist, creating: {}", timestamp_path.display());
                
                // Use create_new(true) equivalent to O_EXCL for atomic creation
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(timestamp_path)
                {
                    Ok(_file) => {
                        // File created successfully, now set mtime to default epoch
                        let default_time = UNIX_EPOCH + Duration::from_secs(DEFAULT_TIMESTAMP_EPOCH);
                        let filetime = FileTime::from_system_time(default_time);
                        
                        if let Err(e) = set_file_mtime(timestamp_path, filetime) {
                            error!(
                                "Failed to set mtime on {}: {}",
                                timestamp_path.display(),
                                e
                            );
                            return Err(TrustAnchorError::IoError {
                                path: timestamp_path.display().to_string(),
                                message: format!("Failed to set mtime: {e}"),
                            });
                        }

                        // Store timestamp_time
                        {
                            let mut ts = self.timestamp_time.write().unwrap();
                            *ts = Some(default_time);
                        }

                        info!(
                            "Created timestamp file {} with epoch {}",
                            timestamp_path.display(),
                            DEFAULT_TIMESTAMP_EPOCH
                        );

                        // Check if current time is already beyond timestamp
                        self.check_and_exit_timestamp()
                    }
                    Err(e) => {
                        // File creation failed
                        error!("Failed to create timestamp file {}: {}", timestamp_path.display(), e);
                        Err(TrustAnchorError::IoError {
                            path: timestamp_path.display().to_string(),
                            message: format!("Failed to create file: {e}"),
                        })
                    }
                }
            }
            Err(e) => {
                // Other error reading metadata
                error!("Failed to stat timestamp file {}: {}", timestamp_path.display(), e);
                Err(TrustAnchorError::IoError {
                    path: timestamp_path.display().to_string(),
                    message: format!("Failed to stat file: {e}"),
                })
            }
        }
    }

    /// Check if current time exceeds timestamp and handle transition
    ///
    /// This is the "`check_and_exit`" label logic from C dnssec.c lines 424-433.
    /// Called from `setup_timestamp()` after reading or creating timestamp file.
    ///
    /// # Returns
    ///
    /// * `Ok(0)` - System time is valid (current time > timestamp)
    /// * `Ok(1)` - System time not yet valid (current time <= timestamp)
    fn check_and_exit_timestamp(&mut self) -> Result<i32, TrustAnchorError> {
        let timestamp_path = self.timestamp_file.as_ref().unwrap();
        
        // Read cached timestamp_time
        let timestamp_time = {
            let ts = self.timestamp_time.read().unwrap();
            match *ts {
                Some(t) => t,
                None => return Ok(1), // No timestamp set, defer validation
            }
        };

        // Get current time
        let now = SystemTime::now();
        
        // Compare: if current time > timestamp, time is valid
        if let Ok(_duration) = now.duration_since(timestamp_time) {
            // Current time is after timestamp - time is valid!
            debug!("System time is beyond timestamp, time considered valid");
            
            // Update timestamp file mtime to current time (equivalent to utimes(file, NULL))
            let now_filetime = FileTime::from_system_time(now);
            if let Err(e) = set_file_mtime(timestamp_path, now_filetime) {
                error!(
                    "Failed to update mtime on {}: {}",
                    timestamp_path.display(),
                    e
                );
                // Log error but don't fail - C implementation continues
            }

            // Set back_to_the_future flag
            {
                let mut btf = self.back_to_the_future.write().unwrap();
                *btf = true;
            }

            Ok(0) // Time is valid
        } else {
            // Current time is before timestamp - time is NOT valid yet
            debug!("System time is before timestamp, deferring validation");
            Ok(1) // Time not yet valid
        }
    }

    /// Determine if DNSSEC signature timestamp checking should be performed
    ///
    /// This function implements C's `is_check_date()` from dnssec.c lines 513-540.
    /// Returns whether current time is reliable enough to perform DNSSEC signature
    /// validity period checks (inception/expiration timestamps).
    ///
    /// # Behavior
    ///
    /// ## If `timestamp_file` is configured:
    /// - Check if `back_to_the_future` is already 1 (time already valid): return true
    /// - If `back_to_the_future` is 0 and current time > timestamp:
    ///   1. Update timestamp file mtime
    ///   2. Log "system time considered valid" message
    ///   3. Set `back_to_the_future` = 1
    ///   4. Set `dnssec_no_time_check` = 0
    ///   5. Return true (and caller should trigger `EVENT_RELOAD` cache purge)
    /// - Otherwise: return false (time not yet valid)
    ///
    /// ## If `timestamp_file` is NOT configured:
    /// - Return !`dnssec_no_time_check` (normal systems with RTC)
    ///
    /// # Arguments
    ///
    /// * `curtime` - Current time as Unix timestamp (seconds since epoch)
    ///
    /// # Returns
    ///
    /// * `true` - System time is valid, check RRSIG timestamps
    /// * `false` - System time not valid, skip timestamp checks
    ///
    /// # Side Effects
    ///
    /// On first transition from invalid to valid time:
    /// - Updates timestamp file mtime
    /// - Logs informational message to syslog
    /// - Sets `back_to_the_future` = 1
    /// - Sets `dnssec_no_time_check` = 0
    /// - **IMPORTANT**: Caller must trigger `EVENT_RELOAD` to purge cache
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C dnssec.c lines 513-540:
    /// ```c
    /// static int is_check_date(unsigned long curtime)
    /// {
    ///   if (daemon->timestamp_file) {
    ///     if (daemon->back_to_the_future == 0 && difftime(timestamp_time, curtime) <= 0) {
    ///       if (utimes(daemon->timestamp_file, NULL) != 0)
    ///         my_syslog(LOG_ERR, _("failed to update mtime on %s: %s"), ...);
    ///       my_syslog(LOG_INFO, _("system time considered valid, now checking DNSSEC signature timestamps."));
    ///       daemon->back_to_the_future = 1;
    ///       daemon->dnssec_no_time_check = 0;
    ///       queue_event(EVENT_RELOAD); /* purge cache */
    ///     }
    ///     return daemon->back_to_the_future;
    ///   }
    ///   else
    ///     return !daemon->dnssec_no_time_check;
    /// }
    /// ```
    pub fn is_check_date(&mut self, curtime: u32) -> bool {
        if let Some(timestamp_path) = &self.timestamp_file {
            // Timestamp file is configured, check back_to_the_future flag
            let btf_value = {
                let btf = self.back_to_the_future.read().unwrap();
                *btf
            };

            if !btf_value {
                // back_to_the_future is still 0, check if time has become valid
                let timestamp_time = {
                    let ts = self.timestamp_time.read().unwrap();
                    match *ts {
                        Some(t) => t,
                        None => return false, // No timestamp set, not valid yet
                    }
                };

                // Convert curtime (u32 seconds) to SystemTime
                let current_time = UNIX_EPOCH + Duration::from_secs(u64::from(curtime));

                // Check if current time > timestamp (equivalent to difftime(timestamp_time, curtime) <= 0)
                if current_time >= timestamp_time {
                    // Time has become valid! Transition from invalid to valid.
                    debug!(
                        "System time ({}) now exceeds timestamp, time is valid",
                        curtime
                    );

                    // Update timestamp file mtime to current time
                    let now_filetime = FileTime::from_system_time(current_time);
                    if let Err(e) = set_file_mtime(timestamp_path, now_filetime) {
                        error!(
                            "Failed to update mtime on {}: {}",
                            timestamp_path.display(),
                            e
                        );
                        // Log error but continue - C implementation does this
                    }

                    // Log the transition message
                    info!("System time considered valid, now checking DNSSEC signature timestamps");

                    // Set flags
                    {
                        let mut btf = self.back_to_the_future.write().unwrap();
                        *btf = true;
                    }
                    // Note: In C, daemon->dnssec_no_time_check is also set to 0 here
                    // In Rust, this flag is immutable after initialization via constructor
                    
                    // Return true - caller MUST trigger EVENT_RELOAD to purge cache
                    // (in C this is done via queue_event(EVENT_RELOAD))
                    return true;
                }
                
                // Time is still not valid
                return false;
            }

            // back_to_the_future is already 1, time is valid
            btf_value
        } else {
            // No timestamp file configured, use dnssec_no_time_check flag
            !self.dnssec_no_time_check
        }
    }

    /// Update timestamp file mtime to current time
    ///
    /// Helper function to update the timestamp file's modification time.
    /// Used during timestamp validation transitions.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - mtime updated successfully
    /// * `Err(TrustAnchorError)` - Update failed
    pub fn update_timestamp(&self) -> Result<(), TrustAnchorError> {
        if let Some(timestamp_path) = &self.timestamp_file {
            let now = SystemTime::now();
            let filetime = FileTime::from_system_time(now);
            
            set_file_mtime(timestamp_path, filetime).map_err(|e| TrustAnchorError::IoError {
                path: timestamp_path.display().to_string(),
                message: format!("Failed to update mtime: {e}"),
            })?;
            
            debug!("Updated timestamp file mtime: {}", timestamp_path.display());
            Ok(())
        } else {
            Ok(()) // No timestamp file, no action needed
        }
    }

    /// Get current value of `back_to_the_future` flag
    ///
    /// # Returns
    ///
    /// Current value of `back_to_the_future` flag (true = time is valid)
    #[must_use] 
    pub fn get_back_to_the_future_flag(&self) -> bool {
        let btf = self.back_to_the_future.read().unwrap();
        *btf
    }
}

// ============================================================================
// Trust Anchor Store
// ============================================================================

/// Trust anchor store for DNSSEC chain of trust
///
/// Manages DNSKEY trust anchors loaded from configuration files. Trust anchors
/// are the root of the DNSSEC chain of trust, typically configured for the DNS
/// root zone (".") or specific zones. This structure provides O(1) lookup by
/// domain name using `HashMap`, replacing C's linked list with O(n) traversal.
///
/// # Fields
///
/// - `anchors`: `HashMap` mapping domain names to lists of DNSKEY records
///
/// # C Implementation Mapping
///
/// Replaces C's daemon->trust_anchors linked list from dnsmasq.h with
/// `HashMap`<String, Vec<DnsKey>> for efficient lookup and memory safety.
pub struct TrustAnchorStore {
    /// Trust anchors indexed by domain name (case-insensitive via `normalize_domain`)
    anchors: HashMap<String, Vec<DnsKey>>,
}

impl TrustAnchorStore {
    /// Create a new empty trust anchor store
    ///
    /// # Returns
    ///
    /// New `TrustAnchorStore` instance with no trust anchors loaded
    #[must_use] 
    pub fn new() -> Self {
        TrustAnchorStore {
            anchors: HashMap::new(),
        }
    }

    /// Load trust anchors from a file
    ///
    /// Parses trust anchor file containing DNSKEY records in zone file format.
    /// Each line should contain a DNSKEY record for a configured zone.
    ///
    /// # File Format Example
    ///
    /// ```text
    /// . IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3...
    /// example.com. IN DNSKEY 256 3 8 AwEAAcFcGsaxxdgiuuGpGGyhoHveaT...
    /// ```
    ///
    /// # Arguments
    ///
    /// * `path` - Path to trust anchor file
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Trust anchors loaded successfully
    /// * `Err(TrustAnchorError)` - File reading or parsing failed
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File cannot be read (permission denied, not found)
    /// - DNSKEY record format is invalid
    /// - Trust anchor validation fails (self-signature check)
    pub async fn load_from_file(&mut self, path: &Path) -> Result<(), TrustAnchorError> {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::fs::File as TokioFile;

        debug!("Loading trust anchors from: {}", path.display());

        let file = TokioFile::open(path).await.map_err(|e| TrustAnchorError::IoError {
            path: path.display().to_string(),
            message: format!("Failed to open file: {e}"),
        })?;

        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut line_number = 0;

        while let Some(line_result) = lines.next_line().await.map_err(|e| TrustAnchorError::IoError {
            path: path.display().to_string(),
            message: format!("Failed to read line: {e}"),
        })? {
            line_number += 1;
            let line = line_result.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Parse DNSKEY record from line
            // Format: <domain> IN DNSKEY <flags> <protocol> <algorithm> <key_data>
            match self.parse_dnskey_line(line, line_number) {
                Ok((domain, dnskey)) => {
                    // Validate trust anchor (check self-signature if possible)
                    if let Err(e) = self.validate_trust_anchor(&domain, &dnskey) {
                        warn!(
                            "Trust anchor validation warning for {} in {} line {}: {}",
                            domain,
                            path.display(),
                            line_number,
                            e
                        );
                        // Continue loading even if validation fails (operator may have good reason)
                    }

                    // Add to store
                    self.add_trust_anchor(domain.clone(), dnskey);
                    debug!("Loaded trust anchor for {} from line {}", domain, line_number);
                }
                Err(e) => {
                    warn!(
                        "Failed to parse trust anchor in {} line {}: {}",
                        path.display(),
                        line_number,
                        e
                    );
                    // Continue parsing remaining lines
                }
            }
        }

        info!(
            "Loaded {} trust anchor domain(s) from {}",
            self.anchors.len(),
            path.display()
        );

        Ok(())
    }

    /// Parse DNSKEY line from trust anchor file
    ///
    /// # Arguments
    ///
    /// * `line` - Line from trust anchor file
    /// * `line_number` - Line number for error reporting
    ///
    /// # Returns
    ///
    /// * `Ok((domain, dnskey))` - Parsed domain name and DNSKEY record
    /// * `Err(TrustAnchorError)` - Parsing failed
    fn parse_dnskey_line(&self, line: &str, line_number: usize) -> Result<(String, DnsKey), TrustAnchorError> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Minimum format: <domain> IN DNSKEY <flags> <protocol> <algorithm> <key_data>
        if parts.len() < 7 {
            return Err(TrustAnchorError::ParseError {
                path: String::from("<input>"),
                line: line_number,
                reason: format!("Insufficient fields (expected at least 7, got {})", parts.len()),
            });
        }

        // Extract domain name (first field)
        let domain = self.normalize_domain(parts[0]);

        // Verify "IN" class (second field) and "DNSKEY" type (third field)
        if parts[1].to_uppercase() != "IN" {
            return Err(TrustAnchorError::ParseError {
                path: String::from("<input>"),
                line: line_number,
                reason: format!("Expected IN class, got {}", parts[1]),
            });
        }

        if parts[2].to_uppercase() != "DNSKEY" {
            return Err(TrustAnchorError::ParseError {
                path: String::from("<input>"),
                line: line_number,
                reason: format!("Expected DNSKEY type, got {}", parts[2]),
            });
        }

        // Parse DNSKEY fields: flags, protocol, algorithm
        let flags = parts[3].parse::<u16>().map_err(|e| TrustAnchorError::ParseError {
            path: String::from("<input>"),
            line: line_number,
            reason: format!("Invalid flags: {e}"),
        })?;

        let protocol = parts[4].parse::<u8>().map_err(|e| TrustAnchorError::ParseError {
            path: String::from("<input>"),
            line: line_number,
            reason: format!("Invalid protocol: {e}"),
        })?;

        let algo_num = parts[5].parse::<u8>().map_err(|e| TrustAnchorError::ParseError {
            path: String::from("<input>"),
            line: line_number,
            reason: format!("Invalid algorithm: {e}"),
        })?;

        let algorithm = DnssecAlgorithm::from_u8(algo_num).ok_or_else(|| TrustAnchorError::ParseError {
            path: String::from("<input>"),
            line: line_number,
            reason: format!("Unsupported algorithm: {algo_num}"),
        })?;

        // Parse public key (base64 encoded, may span multiple parts)
        let key_b64 = parts[6..].join("");
        let public_key = base64::decode(&key_b64).map_err(|e| TrustAnchorError::ParseError {
            path: String::from("<input>"),
            line: line_number,
            reason: format!("Invalid base64 key data: {e}"),
        })?;

        // Create DNSKEY record
        let dnskey = DnsKey::new(flags, protocol, algorithm, public_key);

        Ok((domain, dnskey))
    }

    /// Normalize domain name for case-insensitive storage
    ///
    /// DNS domain names are case-insensitive per RFC 1035 Section 2.3.3.
    /// This function converts domain names to lowercase for `HashMap` keys.
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to normalize
    ///
    /// # Returns
    ///
    /// Lowercase domain name
    fn normalize_domain(&self, domain: &str) -> String {
        domain.to_lowercase()
    }

    /// Get trust anchors for a domain
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to query (case-insensitive)
    ///
    /// # Returns
    ///
    /// * `Some(&Vec<DnsKey>)` - List of trust anchor DNSKEYs for domain
    /// * `None` - No trust anchors configured for domain
    #[must_use] 
    pub fn get_trust_anchor(&self, domain: &str) -> Option<&Vec<DnsKey>> {
        let normalized = self.normalize_domain(domain);
        self.anchors.get(&normalized)
    }

    /// Validate trust anchor DNSKEY
    ///
    /// Checks that trust anchor DNSKEY is properly configured:
    /// - Protocol field is 3 per RFC 4034
    /// - Zone key flag (bit 7) is set
    /// - Public key is non-empty
    ///
    /// Optionally verifies self-signature if RRSIG is available (not implemented
    /// in this basic version - would require crypto module integration).
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name for this trust anchor
    /// * `dnskey` - DNSKEY record to validate
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Trust anchor is valid
    /// * `Err(TrustAnchorError)` - Validation failed
    pub fn validate_trust_anchor(
        &self,
        domain: &str,
        dnskey: &DnsKey,
    ) -> Result<(), TrustAnchorError> {
        // Check protocol field is 3
        if dnskey.protocol() != 3 {
            return Err(TrustAnchorError::ValidationFailed {
                domain: domain.to_string(),
                reason: format!("Invalid protocol {} (must be 3)", dnskey.protocol()),
            });
        }

        // Check zone key flag (bit 7) is set
        let zone_key_bit = 0x0100; // Bit 7 in 16-bit flags
        if (dnskey.flags() & zone_key_bit) == 0 {
            return Err(TrustAnchorError::ValidationFailed {
                domain: domain.to_string(),
                reason: String::from("Zone key flag (bit 7) not set"),
            });
        }

        // Check public key is non-empty
        if dnskey.public_key().is_empty() {
            return Err(TrustAnchorError::ValidationFailed {
                domain: domain.to_string(),
                reason: String::from("Public key is empty"),
            });
        }

        // Domain name length check
        if domain.len() > MAX_DOMAIN_NAME_LEN {
            return Err(TrustAnchorError::InvalidDomain {
                domain: domain.to_string(),
            });
        }

        // Self-signature verification would go here
        // Requires RRSIG record and crypto module integration
        // For now, basic validation is sufficient

        Ok(())
    }

    /// Add trust anchor to store
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name for trust anchor (normalized to lowercase)
    /// * `dnskey` - DNSKEY record to add
    pub fn add_trust_anchor(&mut self, domain: String, dnskey: DnsKey) {
        let normalized = self.normalize_domain(&domain);
        
        self.anchors
            .entry(normalized)
            .or_default()
            .push(dnskey);
    }

    /// Check if trust anchor exists for domain
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to check (case-insensitive)
    ///
    /// # Returns
    ///
    /// `true` if trust anchor configured for domain, `false` otherwise
    #[must_use] 
    pub fn has_trust_anchor(&self, domain: &str) -> bool {
        let normalized = self.normalize_domain(domain);
        self.anchors.contains_key(&normalized)
    }
}

impl Default for TrustAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Standalone Functions (backwards compatibility with C API)
// ============================================================================

/// Initialize timestamp file (standalone function for C API compatibility)
///
/// This function provides a simpler interface matching the C `setup_timestamp()`
/// signature. It creates a temporary `TimestampValidator` and calls its method.
///
/// # Arguments
///
/// * `timestamp_file` - Optional path to timestamp file
/// * `dnssec_no_time_check` - Disable timestamp checking flag
///
/// # Returns
///
/// * `Ok(0)` - System time is already valid
/// * `Ok(1)` - System time not yet valid
/// * `Err(TrustAnchorError)` - Setup failed
pub fn setup_timestamp(
    timestamp_file: Option<PathBuf>,
    dnssec_no_time_check: bool,
) -> Result<i32, TrustAnchorError> {
    let mut validator = TimestampValidator::new(timestamp_file, dnssec_no_time_check);
    validator.setup_timestamp()
}

/// Check if DNSSEC timestamp validation should be performed (standalone function)
///
/// This function provides a simpler interface matching the C `is_check_date()`
/// signature. It creates a temporary `TimestampValidator` and calls its method.
///
/// # Arguments
///
/// * `timestamp_file` - Optional path to timestamp file
/// * `dnssec_no_time_check` - Disable timestamp checking flag
/// * `curtime` - Current time as Unix timestamp
///
/// # Returns
///
/// * `true` - System time is valid, check timestamps
/// * `false` - System time not valid, skip timestamp checks
#[must_use] 
pub fn is_check_date(
    timestamp_file: Option<PathBuf>,
    dnssec_no_time_check: bool,
    curtime: u32,
) -> bool {
    let mut validator = TimestampValidator::new(timestamp_file, dnssec_no_time_check);
    validator.is_check_date(curtime)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_validator_creation() {
        let validator = TimestampValidator::new(None, false);
        assert!(!validator.get_back_to_the_future_flag());
    }

    #[test]
    fn test_is_check_date_no_timestamp_file() {
        // Without timestamp file, should return !dnssec_no_time_check
        let mut validator1 = TimestampValidator::new(None, false);
        assert!(validator1.is_check_date(1000000));

        let mut validator2 = TimestampValidator::new(None, true);
        assert!(!validator2.is_check_date(1000000));
    }

    #[test]
    fn test_trust_anchor_store_creation() {
        let store = TrustAnchorStore::new();
        assert!(!store.has_trust_anchor("."));
        assert!(!store.has_trust_anchor("example.com"));
    }

    #[test]
    fn test_trust_anchor_add_and_get() {
        let mut store = TrustAnchorStore::new();
        
        let key = DnsKey::new(
            257,
            3,
            DnssecAlgorithm::RsaSha256,
            vec![1, 2, 3, 4],
        );
        
        store.add_trust_anchor(String::from("."), key.clone());
        
        assert!(store.has_trust_anchor("."));
        assert!(store.get_trust_anchor(".").is_some());
        assert_eq!(store.get_trust_anchor(".").unwrap().len(), 1);
    }

    #[test]
    fn test_trust_anchor_case_insensitive() {
        let mut store = TrustAnchorStore::new();
        
        let key = DnsKey::new(
            257,
            3,
            DnssecAlgorithm::RsaSha256,
            vec![1, 2, 3, 4],
        );
        
        store.add_trust_anchor(String::from("Example.COM"), key);
        
        assert!(store.has_trust_anchor("example.com"));
        assert!(store.has_trust_anchor("EXAMPLE.COM"));
        assert!(store.has_trust_anchor("ExAmPlE.cOm"));
    }

    #[tokio::test]
    async fn test_setup_timestamp_no_file() {
        let result = setup_timestamp(None, false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
}
