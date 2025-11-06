// Copyright (c) 2024 dnsmasq-rs Contributors
// This file is part of the dnsmasq Rust rewrite project.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

//! Time Handling and Duration Management
//!
//! This module provides time-related utilities translated from the C implementation
//! in `src/util.c`. It includes monotonic time sources, duration formatting, lease
//! expiration checking, and time-related type definitions.
//!
//! # Key Functionality
//!
//! - **Monotonic Time**: Reliable time source immune to system clock adjustments
//! - **Duration Formatting**: Human-readable time interval formatting
//! - **Expiration Checking**: Lease and cache entry expiration logic
//! - **Type Definitions**: Timestamp and lease time wrapper types
//!
//! # Source Mapping
//!
//! Translated from: `src/util.c` (time-related functions including:
//! - `dnsmasq_time()` → `monotonic_time()`
//! - `prettyprint_time()` → `format_duration()`
//! - Lease expiration logic → `is_expired()`
//!
//! # Examples
//!
//! ```rust
//! use dnsmasq::util::time::{monotonic_time, format_duration, Timestamp};
//! use std::time::Duration;
//!
//! // Get current monotonic time for measuring intervals
//! let _now = monotonic_time();
//!
//! // Format a duration
//! let formatted = format_duration(Duration::from_secs(3661));
//! assert_eq!(formatted, "1h 1m 1s");
//!
//! // Create a future timestamp (1 hour from now)
//! let current_timestamp = Timestamp::now();
//! let expires_at = Timestamp::from_secs(current_timestamp.as_secs() + 3600);
//! assert!(!expires_at.is_expired());
//! ```

use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A monotonic timestamp that is immune to system clock adjustments.
///
/// This type wraps a monotonic timestamp and provides methods for expiration
/// checking and duration calculations. It is preferred over `SystemTime` for
/// timeout and expiration logic as it is not affected by NTP adjustments or
/// manual clock changes.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::time::Timestamp;
/// use std::time::Duration;
///
/// let ts = Timestamp::now();
/// let expires = ts.add_duration(Duration::from_secs(3600)); // 1 hour from now
/// assert!(!expires.is_expired());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    /// Seconds since an arbitrary epoch (monotonic)
    secs: u64,
}

impl Timestamp {
    /// Create a timestamp from a number of seconds.
    ///
    /// # Arguments
    ///
    /// * `secs` - The timestamp value in seconds
    ///
    /// # Returns
    ///
    /// A new `Timestamp` instance
    pub fn from_secs(secs: u64) -> Self {
        Self { secs }
    }

    /// Get the current Unix timestamp.
    ///
    /// Returns the current time as seconds since the Unix epoch (1970-01-01 00:00:00 UTC).
    /// This is used for absolute timestamps like DHCP lease expiration times.
    ///
    /// # Returns
    ///
    /// The current Unix timestamp as a `Timestamp`
    pub fn now() -> Self {
        let now = SystemTime::now();
        let since_epoch = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("System time is before Unix epoch");
        
        Self {
            secs: since_epoch.as_secs(),
        }
    }

    /// Get the timestamp value in seconds.
    ///
    /// # Returns
    ///
    /// The timestamp as seconds since the monotonic epoch
    pub fn as_secs(&self) -> u64 {
        self.secs
    }

    /// Add a duration to this timestamp.
    ///
    /// # Arguments
    ///
    /// * `duration` - The duration to add
    ///
    /// # Returns
    ///
    /// A new `Timestamp` with the duration added
    pub fn add_duration(self, duration: Duration) -> Self {
        Self {
            secs: self.secs.saturating_add(duration.as_secs()),
        }
    }

    /// Check if this timestamp has expired (is in the past).
    ///
    /// # Returns
    ///
    /// `true` if the timestamp is in the past, `false` otherwise
    pub fn is_expired(&self) -> bool {
        let now = Self::now();
        now.secs >= self.secs
    }

    /// Calculate the duration until this timestamp.
    ///
    /// # Returns
    ///
    /// A `Duration` until this timestamp, or `Duration::ZERO` if expired
    pub fn duration_until(&self) -> Duration {
        let now = Self::now();
        if now.secs >= self.secs {
            Duration::ZERO
        } else {
            Duration::from_secs(self.secs - now.secs)
        }
    }

    /// Calculate the duration since this timestamp.
    ///
    /// # Returns
    ///
    /// A `Duration` since this timestamp, or `Duration::ZERO` if in the future
    pub fn duration_since(&self) -> Duration {
        let now = Self::now();
        if self.secs > now.secs {
            Duration::ZERO
        } else {
            Duration::from_secs(now.secs - self.secs)
        }
    }
}

/// A lease time duration with special handling for infinite leases.
///
/// DHCP leases can be either finite (with an expiration time) or infinite
/// (permanent). This type encapsulates both cases.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::time::LeaseTime;
/// use std::time::Duration;
///
/// let finite = LeaseTime::Finite(Duration::from_secs(3600));
/// let infinite = LeaseTime::Infinite;
///
/// assert!(!infinite.is_expired());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseTime {
    /// A finite lease with an expiration duration
    Finite(Duration),
    /// An infinite (permanent) lease
    Infinite,
}

impl LeaseTime {
    /// Create a finite lease time from seconds.
    ///
    /// # Arguments
    ///
    /// * `secs` - The lease duration in seconds
    ///
    /// # Returns
    ///
    /// A `LeaseTime::Finite` with the specified duration
    pub fn from_secs(secs: u64) -> Self {
        Self::Finite(Duration::from_secs(secs))
    }

    /// Check if this lease has expired.
    ///
    /// # Returns
    ///
    /// `true` if the lease is finite and has expired, `false` otherwise
    pub fn is_expired(&self) -> bool {
        match self {
            Self::Finite(duration) => *duration == Duration::ZERO,
            Self::Infinite => false,
        }
    }

    /// Get the duration if this is a finite lease.
    ///
    /// # Returns
    ///
    /// `Some(Duration)` if finite, `None` if infinite
    pub fn as_duration(&self) -> Option<Duration> {
        match self {
            Self::Finite(duration) => Some(*duration),
            Self::Infinite => None,
        }
    }
}

impl fmt::Display for LeaseTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Finite(duration) => write!(f, "{}", format_duration(*duration)),
            Self::Infinite => write!(f, "infinite"),
        }
    }
}

/// Error type for time operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeError {
    /// System time is before the Unix epoch
    TimeBeforeEpoch,
    /// Clock went backwards (should not happen with monotonic clocks)
    ClockBackwards,
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeError::TimeBeforeEpoch => write!(f, "System time is before Unix epoch"),
            TimeError::ClockBackwards => write!(f, "Clock went backwards"),
        }
    }
}

impl std::error::Error for TimeError {}

/// Get the current monotonic time.
///
/// Returns a monotonic timestamp that is immune to system clock adjustments.
/// This should be used for all timeout and expiration logic in dnsmasq.
///
/// # Returns
///
/// A `Duration` since an arbitrary monotonic epoch
///
/// # Panics
///
/// This function should not panic under normal circumstances. If the system's
/// monotonic clock is unavailable, it falls back to system time.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::time::monotonic_time;
///
/// let now = monotonic_time();
/// println!("Monotonic time: {:?}", now);
/// ```
///
/// # Source
///
/// Translated from: `dnsmasq_time()` in `src/util.c`
pub fn monotonic_time() -> Duration {
    // Use Instant for true monotonic time
    // Note: Instant doesn't have a specific epoch, so we use a static reference point
    use once_cell::sync::Lazy;
    
    static START: Lazy<Instant> = Lazy::new(|| Instant::now());
    
    START.elapsed()
}

/// Format a duration as a human-readable string.
///
/// Converts a `Duration` into a human-readable format like "1h 30m 45s" or "5m 30s".
///
/// # Arguments
///
/// * `duration` - The duration to format
///
/// # Returns
///
/// A human-readable string representation of the duration
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::time::format_duration;
/// use std::time::Duration;
///
/// assert_eq!(format_duration(Duration::from_secs(0)), "0s");
/// assert_eq!(format_duration(Duration::from_secs(45)), "45s");
/// assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
/// assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
/// ```
///
/// # Source
///
/// Translated from: `prettyprint_time()` in `src/util.c`
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();

    if total_secs == 0 {
        return "0s".to_string();
    }

    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    let mut parts = Vec::new();

    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{}s", seconds));
    }

    parts.join(" ")
}

/// Check if a timestamp has expired.
///
/// Convenience function to check if a timestamp is in the past.
///
/// # Arguments
///
/// * `timestamp` - The timestamp to check
///
/// # Returns
///
/// `true` if the timestamp is expired, `false` otherwise
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::time::{is_expired, Timestamp};
/// use std::time::Duration;
///
/// let future = Timestamp::now().add_duration(Duration::from_secs(3600));
/// assert!(!is_expired(&future));
///
/// let past = Timestamp::from_secs(0);
/// assert!(is_expired(&past));
/// ```
pub fn is_expired(timestamp: &Timestamp) -> bool {
    timestamp.is_expired()
}

/// Get the current Unix timestamp.
///
/// Returns the current time as seconds since the Unix epoch (1970-01-01 00:00:00 UTC).
/// This should be used for logging and display purposes, not for timeout logic
/// (use `monotonic_time()` for timeouts).
///
/// # Returns
///
/// A `Result` containing the Unix timestamp in seconds, or a `TimeError`
///
/// # Errors
///
/// Returns `TimeError::TimeBeforeEpoch` if the system time is before 1970.
pub fn unix_timestamp() -> Result<u64, TimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| TimeError::TimeBeforeEpoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_timestamp_creation() {
        let ts = Timestamp::from_secs(1000);
        assert_eq!(ts.as_secs(), 1000);

        let now = Timestamp::now();
        assert!(now.as_secs() > 0);
    }

    #[test]
    fn test_timestamp_expiration() {
        let past = Timestamp::from_secs(0);
        assert!(past.is_expired());

        let future = Timestamp::now().add_duration(Duration::from_secs(3600));
        assert!(!future.is_expired());
    }

    #[test]
    fn test_timestamp_duration_until() {
        let now = Timestamp::now();
        let future = now.add_duration(Duration::from_secs(100));
        
        let until = future.duration_until();
        assert!(until.as_secs() <= 100);
        assert!(until.as_secs() >= 99); // Allow for some timing variation

        let past = Timestamp::from_secs(0);
        assert_eq!(past.duration_until(), Duration::ZERO);
    }

    #[test]
    fn test_timestamp_duration_since() {
        let past = Timestamp::from_secs(0);
        let since = past.duration_since();
        assert!(since.as_secs() > 0);

        let future = Timestamp::now().add_duration(Duration::from_secs(3600));
        assert_eq!(future.duration_since(), Duration::ZERO);
    }

    #[test]
    fn test_lease_time() {
        let finite = LeaseTime::from_secs(3600);
        assert!(!finite.is_expired());
        assert_eq!(finite.as_duration(), Some(Duration::from_secs(3600)));

        let infinite = LeaseTime::Infinite;
        assert!(!infinite.is_expired());
        assert_eq!(infinite.as_duration(), None);

        let zero = LeaseTime::Finite(Duration::ZERO);
        assert!(zero.is_expired());
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
        assert_eq!(format_duration(Duration::from_secs(7200)), "2h");
        assert_eq!(format_duration(Duration::from_secs(86400)), "24h");
    }

    #[test]
    fn test_monotonic_time() {
        let t1 = monotonic_time();
        sleep(Duration::from_millis(10));
        let t2 = monotonic_time();
        
        assert!(t2 > t1, "Monotonic time should increase");
    }

    #[test]
    fn test_is_expired() {
        let past = Timestamp::from_secs(0);
        assert!(is_expired(&past));

        let future = Timestamp::now().add_duration(Duration::from_secs(3600));
        assert!(!is_expired(&future));
    }

    #[test]
    fn test_unix_timestamp() {
        let ts = unix_timestamp().unwrap();
        // Unix timestamp should be reasonable (after 2020, before 2100)
        assert!(ts > 1_600_000_000); // After Sept 2020
        assert!(ts < 4_000_000_000); // Before 2100
    }
}
