// Copyright (c) 2024 dnsmasq-rs Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Time handling utilities providing monotonic time sources, timestamp conversion,
// duration formatting, and broken RTC fallback.
//
// Translated from: src/util.c (dnsmasq_time, prettyprint_time)

//! # Time Handling Utilities
//!
//! This module provides time-related functionality for dnsmasq, including:
//!
//! - **Monotonic Time Tracking**: High-resolution monotonic clock for measuring intervals
//!   without being affected by system clock adjustments
//! - **Duration Formatting**: Human-readable formatting of time intervals (e.g., "5d 3h 20m")
//! - **Expiration Checking**: Helper functions for DNS cache TTL and DHCP lease expiration
//! - **Broken RTC Support**: Fallback to SystemTime for embedded systems without reliable
//!   hardware clocks (enabled via `broken-rtc` feature)
//!
//! ## C Source Mapping
//!
//! This module replaces the following functions from `src/util.c`:
//!
//! - `dnsmasq_time()` → `monotonic_time()`: Returns seconds since process start
//! - `prettyprint_time()` → `format_duration()`: Formats duration as human-readable string
//!
//! ## Thread Safety
//!
//! All functions in this module are thread-safe. The process start time is initialized
//! once using `std::sync::OnceLock` and subsequent reads are safe from any thread.
//!
//! ## Usage Examples
//!
//! ```rust
//! use dnsmasq::util::time::{init_time_source, monotonic_time, format_duration, is_expired};
//!
//! // Initialize time source (call once during startup)
//! init_time_source();
//!
//! // Get current monotonic time (seconds since process start)
//! let now = monotonic_time();
//!
//! // Check if a lease has expired
//! let lease_start = monotonic_time();
//! let lease_duration = 3600; // 1 hour
//! // ... time passes ...
//! if is_expired(lease_start, lease_duration) {
//!     println!("Lease has expired!");
//! }
//!
//! // Format duration for display
//! let formatted = format_duration(7322); // 2h2m2s
//! println!("Lease time: {}", formatted);
//! ```

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Type alias for timestamps representing seconds since process start.
///
/// This is a monotonic timestamp that increases steadily and is not affected
/// by system clock adjustments. Used throughout dnsmasq for cache TTL, lease
/// expiration, and timeout calculations.
///
/// Note: Unlike Unix timestamps, this represents elapsed seconds since the
/// process started, not since the Unix epoch.
pub type Timestamp = u64;

/// Type alias for lease durations in seconds.
///
/// Represents the duration of a DHCP lease. The special value `INFINITE_LEASE`
/// indicates a lease that never expires (typically used for static reservations).
pub type LeaseTime = u64;

/// Special value indicating an infinite (never-expiring) lease.
///
/// This value (u64::MAX) is used in DHCP to indicate static leases or permanent
/// address assignments. Corresponds to C's `0xffffffff` (when stored in u32).
pub const INFINITE_LEASE: u64 = u64::MAX;

/// Seconds per minute (60).
pub const SECS_PER_MINUTE: u64 = 60;

/// Seconds per hour (3600).
pub const SECS_PER_HOUR: u64 = 3600;

/// Seconds per day (86400).
pub const SECS_PER_DAY: u64 = 86400;

/// Seconds per week (604800).
pub const SECS_PER_WEEK: u64 = 604800;

/// Process start time (monotonic clock reference point).
///
/// This static stores the `Instant` when the process started, or when
/// `init_time_source()` was first called. All subsequent calls to
/// `monotonic_time()` return elapsed seconds since this instant.
///
/// On systems with the `broken-rtc` feature enabled, this uses `SystemTime`
/// instead of `Instant` as a fallback for embedded systems without reliable
/// hardware clocks.
static START_TIME: OnceLock<Instant> = OnceLock::new();

/// Process start time for broken-rtc systems (SystemTime fallback).
///
/// Only used when the `broken-rtc` feature is enabled. Stores the `SystemTime`
/// when the process started as a fallback for systems without reliable
/// monotonic clocks.
#[cfg(feature = "broken-rtc")]
static START_TIME_SYSTEM: OnceLock<SystemTime> = OnceLock::new();

/// Initialize the time source (must be called before using `monotonic_time()`).
///
/// This function captures the current time as the reference point for all
/// future monotonic time measurements. It should be called once during
/// daemon initialization (typically in `main()` before starting the event loop).
///
/// ## Thread Safety
///
/// This function is thread-safe and idempotent. Multiple calls will have no
/// effect after the first call successfully initializes the time source.
///
/// ## Platform Behavior
///
/// - **Normal systems**: Uses `std::time::Instant` for monotonic high-resolution time
/// - **Broken RTC systems** (with `broken-rtc` feature): Uses `std::time::SystemTime`
///   as a fallback, though this can jump if the system clock is adjusted
///
/// ## C Implementation Note
///
/// The C version implicitly initializes on first call to `dnsmasq_time()`.
/// The Rust version requires explicit initialization to ensure deterministic
/// behavior and avoid the overhead of initialization checks on every call.
///
/// ## Examples
///
/// ```rust
/// use dnsmasq::util::time::init_time_source;
///
/// fn main() {
///     // Initialize time tracking at program startup
///     init_time_source();
///     
///     // Now safe to call monotonic_time() from anywhere
///     // ...
/// }
/// ```
pub fn init_time_source() {
    // Initialize the primary time source (Instant)
    START_TIME.get_or_init(Instant::now);
    
    // Also initialize the broken-rtc fallback if the feature is enabled
    #[cfg(feature = "broken-rtc")]
    {
        START_TIME_SYSTEM.get_or_init(SystemTime::now);
    }
}

/// Get current monotonic time in seconds since process start.
///
/// Returns the number of seconds elapsed since the time source was initialized
/// (via `init_time_source()` or the first call to this function). This is a
/// monotonic counter that always increases and is never affected by system
/// clock adjustments, NTP synchronization, or daylight saving time changes.
///
/// ## Return Value
///
/// Seconds elapsed since process start as a `u64`. This value:
/// - Always increases (never goes backward)
/// - Is not affected by system clock changes
/// - Represents relative time, not absolute time
/// - Starts at 0 when the process begins
///
/// ## Platform Behavior
///
/// - **Default**: Uses `std::time::Instant` (CLOCK_MONOTONIC on Unix)
/// - **With `broken-rtc` feature**: Falls back to `SystemTime` for embedded
///   systems without reliable hardware clocks
///
/// ## C Implementation Mapping
///
/// Replaces `dnsmasq_time()` from `src/util.c`:
/// ```c
/// #ifdef HAVE_BROKEN_RTC
///   struct timespec ts;
///   if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
///     die(_("cannot read monotonic clock: %s"), NULL, EC_MISC);
///   return ts.tv_sec;
/// #else
///   return time(NULL);
/// #endif
/// ```
///
/// ## Panics
///
/// Panics if `init_time_source()` was not called before this function.
/// This is a programming error and indicates improper daemon initialization.
///
/// ## Thread Safety
///
/// This function is thread-safe and can be called from any thread after
/// initialization.
///
/// ## Examples
///
/// ```rust
/// use dnsmasq::util::time::{init_time_source, monotonic_time};
///
/// init_time_source();
///
/// let start = monotonic_time();
/// // ... do some work ...
/// let elapsed = monotonic_time() - start;
/// println!("Operation took {} seconds", elapsed);
/// ```
pub fn monotonic_time() -> u64 {
    #[cfg(not(feature = "broken-rtc"))]
    {
        // Primary implementation: use high-resolution monotonic clock
        let start = START_TIME
            .get()
            .expect("init_time_source() must be called before monotonic_time()");
        start.elapsed().as_secs()
    }
    
    #[cfg(feature = "broken-rtc")]
    {
        // Fallback for embedded systems without reliable RTC
        let start = START_TIME_SYSTEM
            .get()
            .expect("init_time_source() must be called before monotonic_time()");
        SystemTime::now()
            .duration_since(*start)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

/// Format a duration in seconds as a human-readable string.
///
/// Converts a duration in seconds to a compact human-readable format using
/// days (d), hours (h), minutes (m), and seconds (s) units. Zero components
/// are omitted for brevity.
///
/// ## Arguments
///
/// * `seconds` - Duration to format, or `INFINITE_LEASE` for infinite duration
///
/// ## Return Value
///
/// A formatted string such as:
/// - `"infinite"` - For `INFINITE_LEASE` or `u32::MAX`
/// - `"5d 3h 20m"` - 5 days, 3 hours, 20 minutes (no seconds shown if zero)
/// - `"2h 15m 30s"` - 2 hours, 15 minutes, 30 seconds
/// - `"45s"` - 45 seconds (no higher units)
/// - `"0s"` - For zero duration
///
/// ## C Implementation Mapping
///
/// Replaces `prettyprint_time()` from `src/util.c`:
/// ```c
/// void prettyprint_time(char *buf, unsigned int t) {
///   if (t == 0xffffffff)
///     sprintf(buf, _("infinite"));
///   else {
///     unsigned int x, p = 0;
///     if ((x = t/86400))
///       p += sprintf(&buf[p], "%ud", x);
///     if ((x = (t/3600)%24))
///       p += sprintf(&buf[p], "%uh", x);
///     if ((x = (t/60)%60))
///       p += sprintf(&buf[p], "%um", x);
///     if ((x = t%60))
///       sprintf(&buf[p], "%us", x);
///   }
/// }
/// ```
///
/// ## Examples
///
/// ```rust
/// use dnsmasq::util::time::{format_duration, INFINITE_LEASE};
///
/// assert_eq!(format_duration(0), "0s");
/// assert_eq!(format_duration(45), "45s");
/// assert_eq!(format_duration(7322), "2h 2m 2s");
/// assert_eq!(format_duration(INFINITE_LEASE), "infinite");
/// assert_eq!(format_duration(u32::MAX as u64), "infinite");
/// ```
pub fn format_duration(seconds: u64) -> String {
    // Handle special infinite lease value (matches C's 0xffffffff check)
    if seconds == INFINITE_LEASE || seconds == u32::MAX as u64 {
        return "infinite".to_string();
    }
    
    // Handle zero duration
    if seconds == 0 {
        return "0s".to_string();
    }
    
    let mut parts = Vec::new();
    let mut remaining = seconds;
    
    // Days
    let days = remaining / SECS_PER_DAY;
    if days > 0 {
        parts.push(format!("{}d", days));
        remaining %= SECS_PER_DAY;
    }
    
    // Hours
    let hours = remaining / SECS_PER_HOUR;
    if hours > 0 {
        parts.push(format!("{}h", hours));
        remaining %= SECS_PER_HOUR;
    }
    
    // Minutes
    let minutes = remaining / SECS_PER_MINUTE;
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
        remaining %= SECS_PER_MINUTE;
    }
    
    // Seconds
    if remaining > 0 {
        parts.push(format!("{}s", remaining));
    }
    
    parts.join(" ")
}

/// Check if a timestamp has expired (current time >= timestamp + timeout).
///
/// Returns `true` if the specified duration has elapsed since the given
/// timestamp. This is used throughout dnsmasq for checking DNS cache entry
/// expiration, DHCP lease expiration, and timeout conditions.
///
/// ## Arguments
///
/// * `timestamp` - Starting time in seconds (from `monotonic_time()`)
/// * `timeout_secs` - Duration in seconds after which expiration occurs
///
/// ## Return Value
///
/// - `true` if `monotonic_time() >= timestamp + timeout_secs` (expired)
/// - `false` if still within the timeout period (not expired)
///
/// ## Examples
///
/// ```rust
/// use dnsmasq::util::time::{init_time_source, monotonic_time, is_expired};
/// use std::thread;
/// use std::time::Duration;
///
/// init_time_source();
///
/// let start = monotonic_time();
/// let timeout = 2; // 2 seconds
///
/// // Immediately after: not expired
/// assert!(!is_expired(start, timeout));
///
/// // After waiting: expired
/// thread::sleep(Duration::from_secs(3));
/// assert!(is_expired(start, timeout));
/// ```
pub fn is_expired(timestamp: Timestamp, timeout_secs: u64) -> bool {
    let now = monotonic_time();
    now >= timestamp.saturating_add(timeout_secs)
}

/// Calculate remaining time before expiration, or None if already expired.
///
/// Returns the number of seconds remaining before the timeout expires.
/// If the timeout has already passed, returns `None`.
///
/// ## Arguments
///
/// * `timestamp` - Starting time in seconds (from `monotonic_time()`)
/// * `timeout_secs` - Duration in seconds after which expiration occurs
///
/// ## Return Value
///
/// - `Some(remaining_seconds)` if not yet expired
/// - `None` if already expired
///
/// ## Examples
///
/// ```rust
/// use dnsmasq::util::time::{init_time_source, monotonic_time, time_remaining};
///
/// init_time_source();
///
/// let start = monotonic_time();
/// let timeout = 3600; // 1 hour
///
/// // Check how much time is left on a lease
/// match time_remaining(start, timeout) {
///     Some(remaining) => println!("{} seconds remaining", remaining),
///     None => println!("Lease has expired"),
/// }
/// ```
pub fn time_remaining(timestamp: Timestamp, timeout_secs: u64) -> Option<u64> {
    let now = monotonic_time();
    let expiry = timestamp.saturating_add(timeout_secs);
    
    if now >= expiry {
        None
    } else {
        Some(expiry - now)
    }
}

/// Convert seconds to a `std::time::Duration`.
///
/// Simple conversion helper for interfacing with standard library APIs
/// that require `Duration` types.
///
/// ## Arguments
///
/// * `secs` - Number of seconds
///
/// ## Return Value
///
/// A `Duration` representing the specified number of seconds.
///
/// ## Examples
///
/// ```rust
/// use dnsmasq::util::time::seconds_to_duration;
/// use std::time::Duration;
///
/// let dur = seconds_to_duration(3600);
/// assert_eq!(dur, Duration::from_secs(3600));
/// ```
pub fn seconds_to_duration(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

/// Convert a `std::time::Duration` to seconds.
///
/// Simple conversion helper for interfacing with standard library APIs
/// that provide `Duration` types. Fractional seconds are truncated.
///
/// ## Arguments
///
/// * `dur` - Duration to convert
///
/// ## Return Value
///
/// Number of whole seconds in the duration (fractional seconds discarded).
///
/// ## Examples
///
/// ```rust
/// use dnsmasq::util::time::duration_to_seconds;
/// use std::time::Duration;
///
/// let dur = Duration::from_secs(3600);
/// assert_eq!(duration_to_seconds(dur), 3600);
///
/// // Fractional seconds are truncated
/// let dur_with_nanos = Duration::new(3600, 500_000_000);
/// assert_eq!(duration_to_seconds(dur_with_nanos), 3600);
/// ```
pub fn duration_to_seconds(dur: Duration) -> u64 {
    dur.as_secs()
}

/// Calculate the expiration timestamp for a lease.
///
/// Given a starting timestamp and lease duration, returns the timestamp
/// at which the lease will expire. This is a simple addition with saturation
/// to prevent overflow.
///
/// ## Arguments
///
/// * `start` - Lease start time in seconds (from `monotonic_time()`)
/// * `lease_secs` - Lease duration in seconds
///
/// ## Return Value
///
/// The expiration timestamp (saturating at `u64::MAX` on overflow).
///
/// ## Examples
///
/// ```rust
/// use dnsmasq::util::time::{init_time_source, monotonic_time, calculate_lease_expiry};
///
/// init_time_source();
///
/// let start = monotonic_time();
/// let lease_duration = 3600; // 1 hour
/// let expires_at = calculate_lease_expiry(start, lease_duration);
///
/// assert_eq!(expires_at, start + lease_duration);
/// ```
pub fn calculate_lease_expiry(start: Timestamp, lease_secs: LeaseTime) -> Timestamp {
    start.saturating_add(lease_secs)
}

/// Calculate remaining time on a lease, or None if expired.
///
/// Given a lease expiration timestamp, returns how many seconds remain
/// before expiration. Returns `None` if the lease has already expired.
///
/// ## Arguments
///
/// * `expiry` - Lease expiration timestamp (from `calculate_lease_expiry()`)
///
/// ## Return Value
///
/// - `Some(remaining_seconds)` if lease is still valid
/// - `None` if lease has expired
///
/// ## Examples
///
/// ```rust
/// use dnsmasq::util::time::{
///     init_time_source, monotonic_time, calculate_lease_expiry, lease_time_remaining
/// };
///
/// init_time_source();
///
/// let start = monotonic_time();
/// let expires_at = calculate_lease_expiry(start, 3600);
///
/// match lease_time_remaining(expires_at) {
///     Some(remaining) => println!("Lease valid for {} more seconds", remaining),
///     None => println!("Lease has expired"),
/// }
/// ```
pub fn lease_time_remaining(expiry: Timestamp) -> Option<u64> {
    let now = monotonic_time();
    
    if now >= expiry {
        None
    } else {
        Some(expiry - now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_init_time_source() {
        // Should not panic
        init_time_source();
        
        // Should be idempotent
        init_time_source();
        init_time_source();
    }

    #[test]
    fn test_monotonic_time_increases() {
        init_time_source();
        
        let time1 = monotonic_time();
        thread::sleep(StdDuration::from_millis(100));
        let time2 = monotonic_time();
        
        assert!(time2 >= time1, "Monotonic time should never decrease");
    }

    #[test]
    fn test_format_duration_zero() {
        assert_eq!(format_duration(0), "0s");
    }

    #[test]
    fn test_format_duration_seconds_only() {
        assert_eq!(format_duration(45), "45s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(60), "1m");
        assert_eq!(format_duration(90), "1m 30s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(3661), "1h 1m 1s");
    }

    #[test]
    fn test_format_duration_days() {
        assert_eq!(format_duration(86400), "1d");
        assert_eq!(format_duration(90061), "1d 1h 1m 1s");
    }

    #[test]
    fn test_format_duration_complex() {
        // 2h 2m 2s = 7200 + 120 + 2 = 7322
        assert_eq!(format_duration(7322), "2h 2m 2s");
    }

    #[test]
    fn test_format_duration_infinite_u64_max() {
        assert_eq!(format_duration(INFINITE_LEASE), "infinite");
    }

    #[test]
    fn test_format_duration_infinite_u32_max() {
        assert_eq!(format_duration(u32::MAX as u64), "infinite");
    }

    #[test]
    fn test_is_expired() {
        init_time_source();
        
        let start = monotonic_time();
        
        // Should not be expired immediately
        assert!(!is_expired(start, 10));
        
        // Should be expired after timeout
        thread::sleep(StdDuration::from_millis(100));
        assert!(is_expired(start, 0));
    }

    #[test]
    fn test_time_remaining() {
        init_time_source();
        
        let start = monotonic_time();
        let timeout = 3600;
        
        // Should have time remaining
        let remaining = time_remaining(start, timeout);
        assert!(remaining.is_some());
        assert!(remaining.unwrap() > 0);
        assert!(remaining.unwrap() <= timeout);
        
        // Test with a timestamp that's guaranteed to be expired
        // Sleep a bit to ensure some time passes
        thread::sleep(StdDuration::from_millis(10));
        let now = monotonic_time();
        
        // Create a timestamp that's definitely in the past
        // If now is 0, this will be 0, and with timeout 0, it should be expired
        let past = now.saturating_sub(1);
        assert_eq!(time_remaining(past, 0), None);
    }

    #[test]
    fn test_seconds_to_duration() {
        let dur = seconds_to_duration(3600);
        assert_eq!(dur.as_secs(), 3600);
    }

    #[test]
    fn test_duration_to_seconds() {
        let dur = StdDuration::from_secs(3600);
        assert_eq!(duration_to_seconds(dur), 3600);
        
        // Test truncation of fractional seconds
        let dur_with_nanos = StdDuration::new(3600, 500_000_000);
        assert_eq!(duration_to_seconds(dur_with_nanos), 3600);
    }

    #[test]
    fn test_calculate_lease_expiry() {
        let start = 1000;
        let duration = 3600;
        let expiry = calculate_lease_expiry(start, duration);
        assert_eq!(expiry, 4600);
    }

    #[test]
    fn test_calculate_lease_expiry_overflow() {
        let start = u64::MAX - 100;
        let duration = 200;
        let expiry = calculate_lease_expiry(start, duration);
        // Should saturate at u64::MAX
        assert_eq!(expiry, u64::MAX);
    }

    #[test]
    fn test_lease_time_remaining() {
        init_time_source();
        
        let now = monotonic_time();
        let future_expiry = now + 3600;
        let past_expiry = now.saturating_sub(10);
        
        // Future expiry should have time remaining
        let remaining = lease_time_remaining(future_expiry);
        assert!(remaining.is_some());
        assert!(remaining.unwrap() > 0);
        
        // Past expiry should return None
        assert_eq!(lease_time_remaining(past_expiry), None);
    }

    #[test]
    fn test_constants() {
        assert_eq!(SECS_PER_MINUTE, 60);
        assert_eq!(SECS_PER_HOUR, 3600);
        assert_eq!(SECS_PER_DAY, 86400);
        assert_eq!(SECS_PER_WEEK, 604800);
        assert_eq!(INFINITE_LEASE, u64::MAX);
    }
}
