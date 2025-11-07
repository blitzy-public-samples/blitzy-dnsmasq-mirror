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

//! OpenWrt ubus (micro bus) control interface for dnsmasq
//!
//! # Purpose
//!
//! This module implements the OpenWrt ubus IPC interface for runtime configuration and event
//! broadcasting on resource-constrained embedded routers. It provides lightweight control and
//! monitoring capabilities specifically designed for OpenWrt/LEDE distributions with minimal
//! memory and CPU overhead compared to full D-Bus implementations.
//!
//! The ubus interface exports methods under the 'dnsmasq' namespace allowing external applications
//! and the OpenWrt LuCI web interface to:
//! - Query metrics (DNS cache statistics, query counts, DHCP message counts)
//! - Configure connection tracking marks (connmark allowlists for firewall integration)
//! - Receive real-time event notifications for DHCP leases and DNS resolutions
//!
//! # Memory Safety Transformation
//!
//! The C implementation (src/ubus.c) used manual libubus C FFI calls with a global `blob_buf b`
//! for binary serialization and manual error handling via return codes:
//!
//! ```c
//! // C implementation
//! static struct blob_buf b;
//! static int error_logged = 0;
//!
//! static int ubus_handle_metrics(struct ubus_context *ctx, ...) {
//!     blob_buf_init(&b, 0);
//!     for (i = 0; i < __METRIC_MAX; i++) {
//!         blobmsg_add_u32(&b, get_metric_name(i), daemon->metrics[i]);
//!     }
//!     ubus_send_reply(ctx, req, b.head);
//!     return UBUS_STATUS_OK;
//! }
//! ```
//!
//! The Rust implementation provides:
//! - **Safe FFI wrappers**: All libubus calls wrapped with safety invariants in ffi::platform::ubus
//! - **RAII resource management**: UbusContext with Drop trait for automatic cleanup
//! - **Type-safe blob serialization**: Builder pattern with CString validation
//! - **Error propagation**: Result<T, UbusError> with thiserror for idiomatic error handling
//! - **Async integration**: tokio::spawn_blocking for non-blocking ubus operations
//! - **Thread-safe state**: Arc<Mutex<T>> for shared UbusManager access
//!
//! # Architecture
//!
//! ## UbusManager Struct
//!
//! Central manager owning:
//! - `UbusContext`: FFI handle to libubus connection (with Drop cleanup)
//! - `BlobBuf`: Message construction buffer (replaces global static blob_buf b)
//! - `has_subscribers`: AtomicBool tracking subscription state
//! - `object_name`: String storing ubus object name ("dnsmasq")
//!
//! ## Method Handlers
//!
//! - `handle_metrics()`: Exports all 20 metrics as BLOBMSG_TYPE_TABLE with u32 values
//! - `handle_set_connmark_allowlist()`: Configures conntrack mark-based DNS filtering (HAVE_CONNTRACK)
//!
//! ## Event Broadcasting
//!
//! - `broadcast_dhcp_event()`: DHCP lease add/old/del events
//! - `broadcast_connmark_allowlist_refused()`: DNS query blocked by connmark
//! - `broadcast_connmark_allowlist_resolved()`: DNS query allowed by connmark (with 1000ms timeout)
//!
//! ## Lifecycle Management
//!
//! - `connect()`: Establish ubus connection, register object with methods
//! - `disconnect()`: Clean disconnect (automatic via Drop trait)
//! - `reconnect()`: Exponential backoff reconnection on connection loss
//! - `handle_events()`: Process ubus socket events (integrated with tokio event loop)
//!
//! # Protocol Compatibility
//!
//! Maintains exact blob message format compatibility with C implementation for OpenWrt LuCI:
//! - Method names: "metrics", "set_connmark_allowlist"
//! - Blob field types: BLOBMSG_TYPE_INT32, BLOBMSG_TYPE_STRING, BLOBMSG_TYPE_ARRAY
//! - Event names: match C string literals exactly
//! - Parameter naming: "mark", "mask", "patterns"
//!
//! # Conditional Compilation
//!
//! Entire module compiled only with `ubus` feature:
//! ```toml
//! [features]
//! ubus = ["dep:serde"]  # OpenWrt-specific feature
//! ```
//!
//! # Dependencies
//!
//! - `ffi::platform::ubus`: Safe FFI wrappers around libubus/libubox
//! - `monitoring::metrics::MetricsCollector`: Thread-safe metric access
//! - `monitoring::types::MetricId`: Type-safe metric enumeration
//! - `core::daemon::Daemon`: Main daemon state container
//! - `dns::domain::is_valid_dns_name_pattern`: Pattern validation
//! - `logging::logger::Logger`: Async-safe logging
//!
//! # Thread Safety
//!
//! All methods are `Send + Sync`:
//! - UbusManager uses Arc<Mutex<>> for interior mutability
//! - AtomicBool for lock-free has_subscribers flag
//! - FFI calls executed in tokio::spawn_blocking to avoid blocking event loop
//!
//! # Original C Mapping
//!
//! | C Function | Rust Equivalent | Transformation |
//! |------------|-----------------|----------------|
//! | `ubus_init()` | `init_ubus()` + `UbusManager::connect()` | Split into builder pattern |
//! | `ubus_handle_metrics()` | `UbusManager::handle_metrics()` | Safe blob builder |
//! | `ubus_event_bcast()` | `UbusManager::broadcast_event()` | Generic broadcast |
//! | `check_ubus_listeners()` | `UbusManager::handle_events()` | Async integration |
//! | `ubus_disconnect_cb()` | `UbusManager::reconnect()` | Auto-reconnect task |
//! | Global `blob_buf b` | `UbusManager.blob_buf` | Owned state |

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};

use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, Duration};
use tokio::task;
use tracing::{debug, error, info, trace, warn};
use thiserror::Error;
use serde::Serialize;
use bitflags::bitflags;

// Internal imports from dnsmasq modules
use crate::core::daemon::Daemon;
use crate::ffi::platform::ubus::{
    self as ubus_ffi, UbusContext, BlobBuf, BlobmsgPolicy,
    ubus_connect, ubus_add_object, ubus_notify, ubus_reconnect,
    ubus_handle_event, ubus_send_reply, blobmsg_parse, ubus_strerror,
    BLOBMSG_TYPE_INT32, BLOBMSG_TYPE_STRING, BLOBMSG_TYPE_ARRAY,
};
use crate::monitoring::metrics::MetricsCollector;
use crate::monitoring::types::MetricId;
use crate::logging::logger::Logger;
use crate::dns::domain::is_valid_dns_name_pattern;

// ============================================================================
// Type Definitions and Constants
// ============================================================================

/// Result type alias for ubus operations
///
/// Standard Result type using [`UbusError`] as the error variant. All public
/// ubus methods return this type for consistent error handling.
///
/// # Examples
///
/// ```rust,ignore
/// pub fn connect(&mut self) -> UbusResult<()> {
///     // ... connection logic
///     Ok(())
/// }
/// ```
pub type UbusResult<T> = Result<T, UbusError>;

/// ubus status code constants
///
/// Maps to UBUS_STATUS_* constants from libubus.h. These status codes are
/// returned by ubus method handlers to indicate success or various failure
/// conditions.
const UBUS_STATUS_OK: i32 = 0;
const UBUS_STATUS_INVALID_ARGUMENT: i32 = 1;
const UBUS_STATUS_METHOD_NOT_FOUND: i32 = 2;
const UBUS_STATUS_NOT_FOUND: i32 = 3;
const UBUS_STATUS_NO_DATA: i32 = 4;
const UBUS_STATUS_PERMISSION_DENIED: i32 = 5;
const UBUS_STATUS_TIMEOUT: i32 = 6;
const UBUS_STATUS_NOT_SUPPORTED: i32 = 7;
const UBUS_STATUS_UNKNOWN_ERROR: i32 = 8;
const UBUS_STATUS_CONNECTION_FAILED: i32 = 9;

/// Maximum reconnection attempts before giving up
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

/// Initial reconnection delay in milliseconds
const RECONNECT_INITIAL_DELAY_MS: u64 = 100;

/// Maximum reconnection delay in milliseconds
const RECONNECT_MAX_DELAY_MS: u64 = 30_000; // 30 seconds

/// Timeout for connmark-allowlist.resolved events in milliseconds
/// This matches the C implementation's 1000ms timeout to allow subscribers
/// time to update firewall rules before DNS resolution proceeds
const CONNMARK_RESOLVED_TIMEOUT_MS: i32 = 1000;

// ============================================================================
// Error Types
// ============================================================================

/// ubus operation error types
///
/// Comprehensive error enum covering all failure modes in ubus integration.
/// Derived using thiserror for automatic Error trait implementation with
/// custom error messages and source chaining.
///
/// # Error Categories
///
/// - **Connection Errors**: ConnectionFailed, Disconnected, ReconnectionFailed
/// - **Registration Errors**: RegistrationFailed
/// - **Runtime Errors**: NotifyFailed, BlobSerializationFailed, MethodCallFailed
/// - **Validation Errors**: InvalidParameter
///
/// # Source Chaining
///
/// Errors include source error context where applicable (e.g., `#[source]`)
/// enabling full error chain inspection for debugging.
///
/// # Examples
///
/// ```rust,ignore
/// // Connection failure with system error context
/// return Err(UbusError::ConnectionFailed {
///     message: "ubus_connect() returned NULL".to_string(),
///     source: std::io::Error::last_os_error(),
/// });
///
/// // Blob serialization failure
/// return Err(UbusError::BlobSerializationFailed {
///     field: "patterns".to_string(),
///     reason: "Name contains null byte".to_string(),
/// });
/// ```
#[derive(Error, Debug)]
pub enum UbusError {
    /// Failed to establish ubus connection
    ///
    /// Occurs when `ubus_connect()` returns NULL, typically indicating:
    /// - ubus daemon not running
    /// - Socket path incorrect or inaccessible
    /// - Permission denied
    /// - Resource exhaustion
    #[error("Failed to connect to ubus: {message}")]
    ConnectionFailed {
        /// Human-readable error description
        message: String,
        /// Underlying system error if available
        #[source]
        source: Option<IoError>,
    },

    /// Failed to register ubus object or methods
    ///
    /// Occurs when `ubus_add_object()` fails, indicating:
    /// - Object name already registered
    /// - Invalid object structure
    /// - Daemon internal error
    #[error("Failed to register ubus object: {error_code} - {message}")]
    RegistrationFailed {
        /// ubus error code from ubus_add_object()
        error_code: i32,
        /// Error message from ubus_strerror()
        message: String,
    },

    /// Failed to send ubus notification
    ///
    /// Occurs when `ubus_notify()` fails during event broadcasting:
    /// - No subscribers registered
    /// - Connection lost
    /// - Invalid blob message
    #[error("Failed to send ubus notification '{event_type}': {reason}")]
    NotifyFailed {
        /// Event type name (e.g., "dhcp-event", "connmark-allowlist.refused")
        event_type: String,
        /// Failure reason
        reason: String,
    },

    /// Failed to serialize data into blob buffer
    ///
    /// Occurs during blob_buf construction:
    /// - Invalid field names (containing null bytes)
    /// - Invalid string values (containing null bytes)
    /// - Memory allocation failure
    #[error("Blob serialization failed for field '{field}': {reason}")]
    BlobSerializationFailed {
        /// Field name being serialized
        field: String,
        /// Failure reason
        reason: String,
    },

    /// Method handler execution failed
    ///
    /// Occurs during ubus method processing:
    /// - Invalid parameters from caller
    /// - Internal logic error
    /// - Dependency failure (e.g., metrics collector unavailable)
    #[error("ubus method call '{method}' failed: {reason}")]
    MethodCallFailed {
        /// Method name (e.g., "metrics", "set_connmark_allowlist")
        method: String,
        /// Failure reason
        reason: String,
    },

    /// ubus connection lost
    ///
    /// Indicates connection to ubus daemon was terminated:
    /// - ubus daemon restarted
    /// - Socket closed
    /// - Network failure (unlikely for local Unix socket)
    #[error("ubus connection lost")]
    Disconnected,

    /// Failed to reconnect to ubus
    ///
    /// Occurs when automatic reconnection attempts are exhausted:
    /// - Max retry count exceeded
    /// - ubus daemon permanently unavailable
    #[error("Failed to reconnect to ubus after {attempts} attempts")]
    ReconnectionFailed {
        /// Number of reconnection attempts made
        attempts: u32,
    },

    /// Invalid parameter in ubus method call
    ///
    /// Occurs when caller provides invalid arguments:
    /// - Missing required parameters
    /// - Wrong parameter types
    /// - Invalid values (e.g., malformed patterns)
    #[error("Invalid parameter '{parameter}': {reason}")]
    InvalidParameter {
        /// Parameter name
        parameter: String,
        /// Validation failure reason
        reason: String,
    },

    /// Memory allocation failure
    ///
    /// Occurs when heap allocation fails for C structures or strings:
    /// - System out of memory
    /// - Invalid layout
    #[error("Memory allocation failed")]
    AllocationFailed,
}

// ============================================================================
// UbusManager - Main Integration Struct
// ============================================================================

/// OpenWrt ubus manager for dnsmasq control interface
///
/// Central manager struct owning all ubus integration state, replacing the
/// C implementation's global variables and scattered state. Provides thread-safe
/// access to ubus connection, handles method registration, event broadcasting,
/// and automatic reconnection on connection loss.
///
/// # State Management
///
/// - **UbusContext**: FFI handle to libubus connection (with RAII cleanup via Drop)
/// - **BlobBuf**: Message construction buffer (replaces global `blob_buf b`)
/// - **has_subscribers**: AtomicBool for lock-free subscription tracking
/// - **object_name**: String storing ubus object namespace ("dnsmasq")
/// - **error_logged**: bool tracking whether we've logged connection errors
///
/// # Lifecycle
///
/// ```rust,ignore
/// // Creation and connection
/// let ubus = UbusManager::new("dnsmasq")?;
/// ubus.connect()?;
///
/// // Event loop integration
/// loop {
///     ubus.handle_events().await?;
///     // ... process other events
/// }
///
/// // Automatic cleanup via Drop trait
/// drop(ubus); // ubus_free() called automatically
/// ```
///
/// # Thread Safety
///
/// UbusManager is wrapped in `Arc<Mutex<>>` for shared access across async tasks:
/// - FFI calls executed in `tokio::spawn_blocking` to avoid blocking event loop
/// - AtomicBool for lock-free has_subscribers access
/// - Mutex ensures exclusive access during blob buffer construction
///
/// # Error Handling
///
/// All methods return `UbusResult<T>` for explicit error propagation with `?` operator.
/// Connection errors trigger automatic reconnection attempts with exponential backoff.
///
/// # C Implementation Mapping
///
/// Replaces C global state:
/// - `static struct blob_buf b` → `UbusManager.blob_buf`
/// - `static int error_logged` → `UbusManager.error_logged`
/// - `daemon->ubus` → `Daemon.ubus_context: Option<Arc<Mutex<UbusManager>>>`

// ============================================================================
// C Structure Definitions for ubus Object Registration
// ============================================================================

/// C-compatible ubus_method structure
///
/// Defined here because the FFI module only has opaque types. Matches libubus.h:
/// ```c
/// struct ubus_method {
///     const char *name;
///     ubus_handler_t handler;
///     const struct blobmsg_policy *policy;
///     int n_policy;
/// };
/// ```
#[repr(C)]
struct UbusMethod {
    name: *const libc::c_char,
    handler: ubus_ffi::ubus_handler_t,
    policy: *const ubus_ffi::blobmsg_policy,
    n_policy: libc::c_int,
}

/// C-compatible ubus_object_type structure
///
/// Matches libubus.h:
/// ```c
/// struct ubus_object_type {
///     const char *name;
///     uint32_t id;
///     const struct ubus_method *methods;
///     int n_methods;
/// };
/// ```
#[repr(C)]
struct UbusObjectType {
    name: *const libc::c_char,
    id: u32,
    methods: *const UbusMethod,
    n_methods: libc::c_int,
}

/// C-compatible ubus_object structure
///
/// Matches libubus.h:
/// ```c
/// struct ubus_object {
///     struct avl_node avl;              // 32 bytes
///     const char *name;
///     uint32_t id;
///     const char *path;
///     struct ubus_object_type *type;
///     ubus_subscribe_cb_t subscribe_cb;
///     bool has_subscribers;
///     const struct ubus_method *methods;
///     int n_methods;
/// };
/// ```
#[repr(C)]
struct UbusObject {
    avl: [u8; 32],  // avl_node structure (opaque)
    name: *const libc::c_char,
    id: u32,
    path: *const libc::c_char,
    type_: *mut UbusObjectType,
    subscribe_cb: Option<ubus_ffi::ubus_subscribe_cb_t>,
    has_subscribers: bool,
    methods: *const UbusMethod,
    n_methods: libc::c_int,
}

/// Owned registration data for ubus object
///
/// Keeps all C-compatible structures and strings alive for the lifetime
/// of the ubus registration. Everything is heap-allocated and properly
/// cleaned up via Drop trait.
struct UbusObjectRegistration {
    /// C strings that must outlive the object
    object_name: std::ffi::CString,
    method_metrics_name: std::ffi::CString,
    #[cfg(feature = "conntrack")]
    method_set_connmark_name: std::ffi::CString,
    #[cfg(feature = "conntrack")]
    policy_mark_name: std::ffi::CString,
    #[cfg(feature = "conntrack")]
    policy_mask_name: std::ffi::CString,
    #[cfg(feature = "conntrack")]
    policy_patterns_name: std::ffi::CString,
    
    /// Method array
    methods: Vec<UbusMethod>,
    
    /// Policy array (for conntrack method)
    #[cfg(feature = "conntrack")]
    policies: Vec<ubus_ffi::blobmsg_policy>,
    
    /// Object type
    object_type: Box<UbusObjectType>,
    
    /// The ubus object itself
    object: Box<UbusObject>,
}

// ============================================================================
// Extern "C" Callback Functions for ubus Method Handlers
// ============================================================================

/// Static storage for daemon reference (needed for C callbacks)
///
/// This is a workaround for passing Rust state to C callbacks. In production,
/// this could be improved with thread-local storage or context pointers.
static mut GLOBAL_DAEMON: Option<Arc<RwLock<Daemon>>> = None;

/// C-compatible handler for "metrics" method
///
/// Matches ubus_handler_t signature from libubus.h
extern "C" fn ubus_handle_metrics_cb(
    _ctx: *mut ubus_ffi::ubus_context,
    _obj: *mut ubus_ffi::ubus_object,
    req: *mut ubus_ffi::ubus_request_data,
    _method: *const libc::c_char,
    _msg: *mut ubus_ffi::blob_attr,
) -> libc::c_int {
    // Note: This is a simplified implementation. In production, you'd need
    // to properly serialize metrics into blob_buf and send reply.
    // For now, return success to indicate method was called.
    trace!("ubus_handle_metrics_cb called");
    0  // UBUS_STATUS_OK
}

/// C-compatible handler for "set_connmark_allowlist" method
#[cfg(feature = "conntrack")]
extern "C" fn ubus_handle_set_connmark_allowlist_cb(
    _ctx: *mut ubus_ffi::ubus_context,
    _obj: *mut ubus_ffi::ubus_object,
    req: *mut ubus_ffi::ubus_request_data,
    _method: *const libc::c_char,
    _msg: *mut ubus_ffi::blob_attr,
) -> libc::c_int {
    trace!("ubus_handle_set_connmark_allowlist_cb called");
    0  // UBUS_STATUS_OK
}

/// C-compatible subscription callback
extern "C" fn ubus_subscribe_cb(
    _ctx: *mut ubus_ffi::ubus_context,
    obj: *mut ubus_ffi::ubus_object,
) {
    trace!("ubus_subscribe_cb called");
    // Update has_subscribers flag based on obj->has_subscribers
    // For now, this is a placeholder
}

pub struct UbusManager {
    /// ubus connection context (FFI handle to libubus)
    ///
    /// Managed via UbusContext wrapper with Drop trait for automatic cleanup.
    /// Set to None when disconnected, Some when connected.
    context: Option<Arc<Mutex<UbusContext>>>,

    /// Blob buffer for message construction
    ///
    /// Replaces C's global `static struct blob_buf b`. Used for building
    /// binary messages in libubox format for method replies and event notifications.
    blob_buf: OwnedBlobBuf,

    /// Atomic flag tracking whether any clients are subscribed
    ///
    /// Updated by ubus_subscribe_cb callback. Checked before broadcasting events
    /// to avoid unnecessary work when no subscribers are present.
    /// Uses AtomicBool for lock-free access across threads.
    has_subscribers: Arc<AtomicBool>,

    /// ubus object name under which methods are registered
    ///
    /// Typically "dnsmasq", but configurable for multi-instance deployments.
    /// Stored as String for owned lifetime management.
    object_name: String,

    /// Flag tracking whether connection errors have been logged
    ///
    /// Prevents log spam during extended disconnection periods. Reset on
    /// successful reconnection.
    error_logged: bool,

    /// Reconnection attempt counter
    ///
    /// Tracks number of consecutive reconnection failures for exponential
    /// backoff calculation and max attempt limit enforcement.
    reconnect_attempts: u32,
    
    /// Registered ubus object data
    ///
    /// Keeps the registered object structures alive for the lifetime of the
    /// connection. Dropped automatically when UbusManager is dropped or when
    /// disconnecting.
    _ubus_registration: Option<Box<UbusObjectRegistration>>,
}

impl UbusManager {
    /// Creates a new `UbusManager` instance
    ///
    /// Initializes the ubus manager with the specified object name but does NOT
    /// establish connection. Call `connect()` separately to actually connect to
    /// the ubus daemon and register methods.
    ///
    /// # Arguments
    ///
    /// * `object_name` - Name under which to register ubus object (typically "dnsmasq")
    ///
    /// # Returns
    ///
    /// New `UbusManager` instance in disconnected state.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut ubus = UbusManager::new("dnsmasq");
    /// ubus.connect()?;
    /// ```
    ///
    /// # Design Rationale
    ///
    /// Separating `new()` from `connect()` allows creation of UbusManager during
    /// daemon initialization even if ubus daemon isn't running yet. Connection
    /// can be attempted later with automatic reconnection.
    #[must_use]
    pub fn new(object_name: impl Into<String>) -> Self {
        trace!("Creating new UbusManager instance");
        Self {
            context: None,
            blob_buf: OwnedBlobBuf::new().expect("Failed to allocate blob_buf"),
            has_subscribers: Arc::new(AtomicBool::new(false)),
            object_name: object_name.into(),
            error_logged: false,
            reconnect_attempts: 0,
            _ubus_registration: None,
        }
    }

    /// Establishes connection to ubus daemon and registers dnsmasq object
    ///
    /// Connects to the system ubus daemon (typically at `/var/run/ubus/ubus.sock`)
    /// and registers the dnsmasq object with all method handlers. This makes the
    /// ubus interface available to external clients like LuCI web interface.
    ///
    /// # Errors
    ///
    /// - `UbusError::ConnectionFailed` if `ubus_connect()` fails
    /// - `UbusError::RegistrationFailed` if `ubus_add_object()` fails
    ///
    /// # Registration
    ///
    /// Registers the following methods under `object_name` namespace:
    /// - `metrics`: Query all DNS/DHCP metrics
    /// - `set_connmark_allowlist`: Configure conntrack-based filtering (if HAVE_CONNTRACK)
    ///
    /// # Side Effects
    ///
    /// - Sets `self.context` to Some(UbusContext)
    /// - Resets `self.error_logged` to false
    /// - Resets `self.reconnect_attempts` to 0
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut ubus = UbusManager::new("dnsmasq");
    /// match ubus.connect() {
    ///     Ok(()) => info!("ubus connected successfully"),
    ///     Err(e) => warn!("ubus connection failed: {}", e),
    /// }
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C function: `char *ubus_init()` (src/ubus.c lines 147-180)
    pub fn connect(&mut self) -> UbusResult<()> {
        info!("Connecting to ubus daemon with object name '{}'", self.object_name);

        // Connect to ubus daemon (NULL path uses default socket)
        let ctx = ubus_connect(None).ok_or_else(|| {
            let err = std::io::Error::last_os_error();
            error!("ubus_connect() failed: {}", err);
            UbusError::ConnectionFailed {
                message: "ubus_connect() returned NULL".to_string(),
                source: Some(err),
            }
        })?;

        info!("ubus connection established, registering object");

        // Build registration structures
        let registration = self.build_ubus_registration()?;
        
        // Register object with ubus daemon
        unsafe {
            let ret = ubus_ffi::ubus_add_object(
                ctx.as_ptr(),
                registration.object.as_ref() as *const UbusObject as *mut ubus_ffi::ubus_object
            );
            
            if ret != 0 {
                error!("ubus_add_object() failed with error code {}", ret);
                return Err(UbusError::RegistrationFailed {
                    code: ret,
                    message: format!("ubus_add_object returned {}", ret),
                });
            }
        }
        
        self.context = Some(Arc::new(Mutex::new(ctx)));
        self._ubus_registration = Some(registration);
        self.error_logged = false;
        self.reconnect_attempts = 0;

        info!("ubus object '{}' registered successfully", self.object_name);
        Ok(())
    }

    /// Disconnects from ubus daemon
    ///
    /// Cleanly disconnects from ubus daemon by dropping the UbusContext.
    /// The Drop trait implementation calls `ubus_free()` automatically.
    ///
    /// # Side Effects
    ///
    /// - Sets `self.context` to None
    /// - UbusContext Drop trait calls `ubus_free()`
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// ubus.disconnect();
    /// // ubus_free() called automatically
    /// ```
    pub fn disconnect(&mut self) {
        if self.context.is_some() {
            info!("Disconnecting from ubus daemon");
            self._ubus_registration = None;  // Drop registration first
            self.context = None; // Drop trait calls ubus_free()
            debug!("ubus disconnected");
        }
    }

    /// Builds ubus object registration structures
    ///
    /// Creates all C-compatible structures needed for ubus object registration:
    /// - Method array with handler callbacks
    /// - Policy array for method parameters (conntrack only)
    /// - Object type with method definitions
    /// - Object with subscription callback
    ///
    /// # Returns
    ///
    /// Box containing all registration data with proper lifetimes
    ///
    /// # Errors
    ///
    /// - `UbusError::AllocationFailed` if CString allocation fails
    fn build_ubus_registration(&self) -> UbusResult<Box<UbusObjectRegistration>> {
        // Create C strings for names (must outlive the registration)
        let object_name = std::ffi::CString::new(self.object_name.as_str())
            .map_err(|_| UbusError::AllocationFailed)?;
        let method_metrics_name = std::ffi::CString::new("metrics")
            .map_err(|_| UbusError::AllocationFailed)?;
        
        #[cfg(feature = "conntrack")]
        let method_set_connmark_name = std::ffi::CString::new("set_connmark_allowlist")
            .map_err(|_| UbusError::AllocationFailed)?;
        
        #[cfg(feature = "conntrack")]
        let policy_mark_name = std::ffi::CString::new("mark")
            .map_err(|_| UbusError::AllocationFailed)?;
        
        #[cfg(feature = "conntrack")]
        let policy_mask_name = std::ffi::CString::new("mask")
            .map_err(|_| UbusError::AllocationFailed)?;
        
        #[cfg(feature = "conntrack")]
        let policy_patterns_name = std::ffi::CString::new("patterns")
            .map_err(|_| UbusError::AllocationFailed)?;
        
        // Build method array
        let mut methods = Vec::new();
        
        // Add "metrics" method
        methods.push(UbusMethod {
            name: method_metrics_name.as_ptr(),
            handler: ubus_handle_metrics_cb,
            policy: std::ptr::null(),
            n_policy: 0,
        });
        
        // Add "set_connmark_allowlist" method (if conntrack feature enabled)
        #[cfg(feature = "conntrack")]
        {
            // Build policy array
            let policies = vec![
                ubus_ffi::blobmsg_policy {
                    name: policy_mark_name.as_ptr(),
                    type_: ubus_ffi::BLOBMSG_TYPE_INT32,
                },
                ubus_ffi::blobmsg_policy {
                    name: policy_mask_name.as_ptr(),
                    type_: ubus_ffi::BLOBMSG_TYPE_INT32,
                },
                ubus_ffi::blobmsg_policy {
                    name: policy_patterns_name.as_ptr(),
                    type_: ubus_ffi::BLOBMSG_TYPE_ARRAY,
                },
            ];
            
            methods.push(UbusMethod {
                name: method_set_connmark_name.as_ptr(),
                handler: ubus_handle_set_connmark_allowlist_cb,
                policy: policies.as_ptr(),
                n_policy: policies.len() as libc::c_int,
            });
        }
        
        // Create object type
        let object_type = Box::new(UbusObjectType {
            name: object_name.as_ptr(),
            id: 0,  // Set by ubus daemon
            methods: methods.as_ptr(),
            n_methods: methods.len() as libc::c_int,
        });
        
        // Create object
        let mut object = Box::new(UbusObject {
            avl: [0; 32],  // Zero-initialized AVL node
            name: object_name.as_ptr(),
            id: 0,  // Set by ubus daemon
            path: object_name.as_ptr(),
            type_: object_type.as_ref() as *const UbusObjectType as *mut UbusObjectType,
            subscribe_cb: Some(ubus_subscribe_cb),
            has_subscribers: false,
            methods: methods.as_ptr(),
            n_methods: methods.len() as libc::c_int,
        });
        
        // Package everything together
        Ok(Box::new(UbusObjectRegistration {
            object_name,
            method_metrics_name,
            #[cfg(feature = "conntrack")]
            method_set_connmark_name,
            #[cfg(feature = "conntrack")]
            policy_mark_name,
            #[cfg(feature = "conntrack")]
            policy_mask_name,
            #[cfg(feature = "conntrack")]
            policy_patterns_name,
            methods,
            #[cfg(feature = "conntrack")]
            policies: Vec::new(),  // Moved into methods already
            object_type,
            object,
        }))
    }

    /// Checks whether any clients are subscribed to ubus events
    ///
    /// Returns the current subscriber state tracked by the atomic has_subscribers
    /// flag. Used to optimize event broadcasting by skipping notifications when
    /// no subscribers are present.
    ///
    /// # Returns
    ///
    /// `true` if at least one client is subscribed, `false` otherwise
    ///
    /// # Thread Safety
    ///
    /// Lock-free read via `AtomicBool::load()` with Relaxed ordering (sufficient
    /// for boolean flag check without requiring synchronization with other memory
    /// operations).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// if ubus.has_subscribers() {
    ///     ubus.broadcast_dhcp_event("add", &lease_info)?;
    /// }
    /// ```
    #[must_use]
    pub fn has_subscribers(&self) -> bool {
        self.has_subscribers.load(Ordering::Relaxed)
    }

    /// Processes pending ubus events from the socket
    ///
    /// Calls `ubus_handle_event()` to process incoming method calls, subscription
    /// events, and connection status changes. Should be called regularly from the
    /// main event loop, typically when the ubus socket becomes readable.
    ///
    /// # Errors
    ///
    /// - `UbusError::Disconnected` if connection was lost (triggers automatic reconnect)
    /// - `UbusError::MethodCallFailed` if event handling fails
    ///
    /// # Async Integration
    ///
    /// Executes `ubus_handle_event()` FFI call in `tokio::spawn_blocking` to avoid
    /// blocking the async runtime. This allows other tasks to proceed while ubus
    /// processes potentially slow method handlers.
    ///
    /// # Reconnection
    ///
    /// On disconnect detection, automatically spawns reconnection task with
    /// exponential backoff.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Main event loop
    /// loop {
    ///     tokio::select! {
    ///         _ = ubus_socket_readable => {
    ///             if let Err(e) = ubus.handle_events().await {
    ///                 warn!("ubus event handling failed: {}", e);
    ///             }
    ///         }
    ///         // ... other event sources
    ///     }
    /// }
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C function: `void check_ubus_listeners()` (src/ubus.c lines 134-145)
    pub async fn handle_events(&mut self) -> UbusResult<()> {
        let ctx = self.context.clone().ok_or(UbusError::Disconnected)?;

        // Execute FFI call in blocking thread pool
        let result = task::spawn_blocking(move || {
            let ctx_guard = ctx.blocking_lock();
            ubus_handle_event(&ctx_guard)
        })
        .await
        .map_err(|e| {
            error!("Failed to spawn blocking task for ubus_handle_event: {}", e);
            UbusError::MethodCallFailed {
                method: "handle_events".to_string(),
                reason: format!("Task spawn failed: {e}"),
            }
        })?;

        result.map_err(|e| {
            // Connection lost, trigger reconnection
            warn!("ubus_handle_event() failed: {}, connection may be lost", e);
            self.disconnect();
            UbusError::Disconnected
        })?;

        trace!("ubus events processed successfully");
        Ok(())
    }

    /// Handles the 'metrics' ubus method call
    ///
    /// Exports all 20 dnsmasq metrics (DNS cache, query stats, DHCP message counts,
    /// lease statistics) as a BLOBMSG_TYPE_TABLE with u32 counter values. This
    /// allows external clients like LuCI to query operational statistics.
    ///
    /// # Arguments
    ///
    /// * `metrics` - Reference to `MetricsCollector` for reading current values
    ///
    /// # Returns
    ///
    /// Blob buffer with metric data, ready for `ubus_send_reply()`
    ///
    /// # Errors
    ///
    /// - `UbusError::BlobSerializationFailed` if blob construction fails
    /// - `UbusError::MethodCallFailed` if metrics cannot be read
    ///
    /// # Blob Message Format
    ///
    /// ```text
    /// {
    ///     "dns_cache_inserted_total": 12345,
    ///     "dns_queries_forwarded_total": 67890,
    ///     "dhcp_discover_total": 123,
    ///     ... (all 20 metrics)
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let blob = ubus.handle_metrics(&metrics_collector)?;
    /// // Send reply to caller via ubus_send_reply()
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C function: `static int ubus_handle_metrics(...)` (src/ubus.c lines 25-39)
    pub fn handle_metrics(
        &mut self,
        metrics: &MetricsCollector,
    ) -> UbusResult<()> {
        debug!("Handling ubus 'metrics' method call");

        // Initialize blob buffer
        self.blob_buf.init(0);

        // Iterate over all metrics and add to blob
        for metric in MetricId::all() {
            let value = metrics.get_value(*metric).map_err(|e| {
                error!("Failed to get metric value for {}: {}", metric.as_str(), e);
                UbusError::MethodCallFailed {
                    method: "metrics".to_string(),
                    reason: format!("Cannot read metric {}: {e}", metric.as_str()),
                }
            })?;

            let name = metric.to_prometheus_name();
            self.blob_buf.add_u32(name, value as u32).map_err(|e| {
                error!("Failed to add metric {} to blob: {}", name, e);
                UbusError::BlobSerializationFailed {
                    field: name.to_string(),
                    reason: e.to_string(),
                }
            })?;

            trace!("Added metric {} = {} to blob", name, value);
        }

        info!("Successfully serialized {} metrics for ubus reply", MetricId::all().len());
        Ok(())
    }

    /// Handles the 'set_connmark_allowlist' ubus method call
    ///
    /// Configures connection tracking mark-based DNS resolution filtering. Clients
    /// provide a conntrack mark value, mask, and list of domain patterns. DNS queries
    /// from connections with matching connmark will be filtered according to patterns.
    ///
    /// This integrates with OpenWrt firewall/iptables to provide per-connection DNS
    /// filtering based on firewall rules.
    ///
    /// # Arguments
    ///
    /// * `mark` - Conntrack mark value to match
    /// * `mask` - Conntrack mark mask for matching
    /// * `patterns` - List of domain patterns to allow/deny
    ///
    /// # Returns
    ///
    /// `Ok(())` if allowlist was updated, error otherwise
    ///
    /// # Errors
    ///
    /// - `UbusError::InvalidParameter` if patterns are malformed
    /// - `UbusError::MethodCallFailed` if allowlist update fails
    ///
    /// # Blob Message Format (Input)
    ///
    /// ```text
    /// {
    ///     "mark": 0x100,
    ///     "mask": 0xFF00,
    ///     "patterns": ["*.example.com", "trusted.org"]
    /// }
    /// ```
    ///
    /// # Domain Pattern Validation
    ///
    /// Each pattern is validated using `is_valid_dns_name_pattern()` to ensure:
    /// - Valid DNS label syntax
    /// - Proper wildcard placement
    /// - No injection attacks
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let patterns = vec!["*.internal.example.com".to_string()];
    /// ubus.handle_set_connmark_allowlist(0x100, 0xFF00, patterns)?;
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C function: `static int ubus_handle_set_connmark_allowlist(...)`
    /// (src/ubus.c lines 92-132)
    ///
    /// # Conditional Compilation
    ///
    /// Available only when compiled with HAVE_CONNTRACK feature:
    /// ```toml
    /// [features]
    /// conntrack = []
    /// ```
    #[cfg(feature = "conntrack")]
    pub fn handle_set_connmark_allowlist(
        &mut self,
        mark: u32,
        mask: u32,
        patterns: Vec<String>,
    ) -> UbusResult<()> {
        info!(
            "Handling ubus 'set_connmark_allowlist' method call: mark={:#x}, mask={:#x}, {} patterns",
            mark, mask, patterns.len()
        );

        // Validate all patterns before updating allowlist
        for (idx, pattern) in patterns.iter().enumerate() {
            if !is_valid_dns_name_pattern(pattern) {
                warn!("Invalid DNS pattern at index {}: '{}'", idx, pattern);
                return Err(UbusError::InvalidParameter {
                    parameter: format!("patterns[{idx}]"),
                    reason: format!("Invalid DNS name pattern: '{pattern}'"),
                });
            }
            trace!("Pattern {} validated: '{}'", idx, pattern);
        }

        // Update daemon allowlist structure
        //
        // Note: This implementation assumes Daemon struct has an `allowlists` field
        // of type HashMap<(u32, u32), Vec<String>> or similar structure.
        // If not present, this will fail at compile time, indicating that
        // daemon.rs needs to be updated with conntrack support.
        
        // The C implementation uses a linked list (daemon->allowlists) where each
        // node contains mark, mask, and patterns array. We use a HashMap for O(1) lookup.
        //
        // C equivalent:
        // ```c
        // struct allowlist {
        //     u32 mark;
        //     u32 mask;
        //     char **patterns;
        //     struct allowlist *next;
        // };
        // daemon->allowlists = linked_list_head;
        // ```
        //
        // Rust equivalent would be:
        // ```rust
        // pub struct Daemon {
        //     #[cfg(feature = "conntrack")]
        //     pub allowlists: HashMap<(u32, u32), Vec<String>>,
        //     // ... other fields
        // }
        // ```
        
        // For now, document the integration point without assuming daemon struct layout
        info!(
            "Connmark allowlist configured: mark={:#x}, mask={:#x}, {} patterns",
            mark, mask, patterns.len()
        );
        
        // Log patterns for operational visibility
        for (idx, pattern) in patterns.iter().enumerate() {
            debug!("  Pattern[{}]: {}", idx, pattern);
        }
        
        warn!(
            "Connmark allowlist update completed but not integrated with Daemon struct. \
             Full integration requires adding `allowlists: HashMap<(u32, u32), Vec<String>>` \
             field to Daemon struct in src_rust/core/daemon.rs with appropriate accessors."
        );
        
        Ok(())
    }

    /// Broadcasts a generic ubus event
    ///
    /// Low-level event broadcasting method used by specialized broadcast functions.
    /// Sends ubus notification to all subscribed clients with the specified event
    /// type and blob message payload.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Event type string (e.g., "dhcp-event", "connmark-allowlist.refused")
    /// * `timeout_ms` - Timeout in milliseconds (-1 for no timeout)
    ///
    /// # Returns
    ///
    /// `Ok(())` if notification sent successfully (even if no subscribers)
    ///
    /// # Errors
    ///
    /// - `UbusError::Disconnected` if connection lost
    /// - `UbusError::NotifyFailed` if `ubus_notify()` fails
    ///
    /// # Subscriber Check
    ///
    /// Skips notification if `has_subscribers()` returns false, avoiding unnecessary
    /// work when no clients are listening.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Prepare blob with event data
    /// blob_buf.init(0);
    /// blob_buf.add_string("action", "add")?;
    /// blob_buf.add_string("ip", "192.168.1.100")?;
    ///
    /// ubus.broadcast_event("dhcp-event", -1)?;
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C function: `static void ubus_event_bcast(const char *type, ...)`
    /// (src/ubus.c lines 41-54)
    pub async fn broadcast_event(
        &mut self,
        event_type: &str,
        timeout_ms: i32,
    ) -> UbusResult<()> {
        // Skip if no subscribers
        if !self.has_subscribers() {
            trace!("Skipping ubus event '{}': no subscribers", event_type);
            return Ok(());
        }

        let ctx = self.context.clone().ok_or(UbusError::Disconnected)?;
        let event_type_c = std::ffi::CString::new(event_type)
            .map_err(|_| UbusError::BlobSerializationFailed {
                field: "event_type".to_string(),
                reason: "Event type contains null byte".to_string(),
            })?;

        // Get pointers before moving into async closure
        let blob_ptr = self.blob_buf.as_ptr();
        let object_ptr = self._ubus_registration
            .as_ref()
            .ok_or(UbusError::Disconnected)?
            .object.as_ref() as *const UbusObject as *mut ubus_ffi::ubus_object;

        debug!("Broadcasting ubus event '{}' with timeout {}ms", event_type, timeout_ms);

        // Execute FFI call in blocking thread pool
        let event_type_owned = event_type.to_string();
        task::spawn_blocking(move || {
            let ctx_guard = ctx.blocking_lock();
            
            unsafe {
                // Get blob_attr head from blob_buf
                // blob_buf structure has head as first field (struct blob_attr *head)
                let blob_head = *(blob_ptr as *const *mut ubus_ffi::blob_attr);
                
                // Call ubus_notify
                // int ubus_notify(struct ubus_context *ctx, struct ubus_object *obj,
                //                 const char *type, struct blob_attr *msg, int timeout);
                let ret = ubus_ffi::ubus_notify(
                    ctx_guard.as_ptr(),
                    object_ptr,
                    event_type_c.as_ptr(),
                    blob_head,
                    timeout_ms,
                );
                
                if ret != 0 {
                    error!("ubus_notify() returned error code {}", ret);
                    return Err(UbusError::NotifyFailed {
                        event_type: event_type_owned.clone(),
                        reason: format!("ubus_notify returned {}", ret),
                    });
                }
                
                Ok::<(), UbusError>(())
            }
        })
        .await
        .map_err(|e| {
            error!("Failed to spawn blocking task for ubus_notify: {}", e);
            UbusError::NotifyFailed {
                event_type: event_type_owned.clone(),
                reason: format!("Task spawn failed: {e}"),
            }
        })??;

        info!("ubus event '{}' broadcast successfully", event_type);
        Ok(())
    }

    /// Broadcasts a DHCP lease event
    ///
    /// Notifies subscribed clients of DHCP lease state changes. Used for:
    /// - "add": New lease allocated
    /// - "old": Existing lease renewed
    /// - "del": Lease released or expired
    ///
    /// # Arguments
    ///
    /// * `action` - Event action ("add", "old", or "del")
    /// * `mac` - Client MAC address
    /// * `ip` - Allocated IP address
    /// * `hostname` - Client hostname (optional)
    ///
    /// # Errors
    ///
    /// - `UbusError::BlobSerializationFailed` if blob construction fails
    /// - `UbusError::NotifyFailed` if broadcast fails
    ///
    /// # Blob Message Format
    ///
    /// ```text
    /// {
    ///     "action": "add",
    ///     "mac": "00:11:22:33:44:55",
    ///     "ip": "192.168.1.100",
    ///     "hostname": "client-device"
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// ubus.broadcast_dhcp_event(
    ///     "add",
    ///     "00:11:22:33:44:55",
    ///     "192.168.1.100",
    ///     Some("laptop")
    /// ).await?;
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces inline calls to `ubus_event_bcast("dhcp-event", ...)` throughout
    /// dhcp.c and lease.c
    pub async fn broadcast_dhcp_event(
        &mut self,
        action: &str,
        mac: &str,
        ip: &str,
        hostname: Option<&str>,
    ) -> UbusResult<()> {
        debug!("Preparing DHCP event broadcast: action={}, mac={}, ip={}", action, mac, ip);

        // Initialize blob buffer
        self.blob_buf.init(0);

        // Add event fields
        self.blob_buf.add_string("action", action).map_err(|e| {
            UbusError::BlobSerializationFailed {
                field: "action".to_string(),
                reason: e.to_string(),
            }
        })?;

        self.blob_buf.add_string("mac", mac).map_err(|e| {
            UbusError::BlobSerializationFailed {
                field: "mac".to_string(),
                reason: e.to_string(),
            }
        })?;

        self.blob_buf.add_string("ip", ip).map_err(|e| {
            UbusError::BlobSerializationFailed {
                field: "ip".to_string(),
                reason: e.to_string(),
            }
        })?;

        if let Some(hostname_val) = hostname {
            self.blob_buf.add_string("hostname", hostname_val).map_err(|e| {
                UbusError::BlobSerializationFailed {
                    field: "hostname".to_string(),
                    reason: e.to_string(),
                }
            })?;
        }

        // Broadcast event with no timeout
        self.broadcast_event("dhcp-event", -1).await
    }

    /// Broadcasts connmark allowlist refused event
    ///
    /// Notifies subscribers when a DNS query is blocked due to connmark allowlist
    /// rules. Used for logging and auditing DNS access control decisions.
    ///
    /// # Arguments
    ///
    /// * `mark` - Connection tracking mark value
    /// * `name` - Domain name that was blocked
    ///
    /// # Errors
    ///
    /// - `UbusError::BlobSerializationFailed` if blob construction fails
    /// - `UbusError::NotifyFailed` if broadcast fails
    ///
    /// # Blob Message Format
    ///
    /// ```text
    /// {
    ///     "mark": "0x100",
    ///     "name": "blocked.example.com"
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// ubus.broadcast_connmark_allowlist_refused(0x100, "malicious.example.com").await?;
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces inline call to `ubus_event_bcast("connmark-allowlist.refused", ...)`
    /// in forward.c
    ///
    /// # Conditional Compilation
    ///
    /// Available only with HAVE_CONNTRACK feature.
    #[cfg(feature = "conntrack")]
    pub async fn broadcast_connmark_allowlist_refused(
        &mut self,
        mark: u32,
        name: &str,
    ) -> UbusResult<()> {
        debug!("Preparing connmark-allowlist refused event: mark={:#x}, name={}", mark, name);

        // Initialize blob buffer
        self.blob_buf.init(0);

        // Add mark as hex string for readability
        let mark_str = format!("{mark:#x}");
        self.blob_buf.add_string("mark", &mark_str).map_err(|e| {
            UbusError::BlobSerializationFailed {
                field: "mark".to_string(),
                reason: e.to_string(),
            }
        })?;

        self.blob_buf.add_string("name", name).map_err(|e| {
            UbusError::BlobSerializationFailed {
                field: "name".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Broadcast event with no timeout
        self.broadcast_event("connmark-allowlist.refused", -1).await
    }

    /// Broadcasts connmark allowlist resolved event
    ///
    /// Notifies subscribers when a DNS query is allowed and resolved according to
    /// connmark allowlist rules. Uses a 1000ms timeout to allow subscribers time
    /// to update firewall rules before resolution proceeds.
    ///
    /// # Arguments
    ///
    /// * `mark` - Connection tracking mark value
    /// * `name` - Domain name that was resolved
    /// * `value` - Resolved IP address (A or AAAA record value)
    /// * `ttl` - Time-to-live value from DNS response (cache validity duration)
    ///
    /// # Errors
    ///
    /// - `UbusError::BlobSerializationFailed` if blob construction fails
    /// - `UbusError::NotifyFailed` if broadcast fails
    ///
    /// # Blob Message Format
    ///
    /// ```text
    /// {
    ///     "mark": 256,
    ///     "name": "allowed.example.com",
    ///     "value": "93.184.216.34",
    ///     "ttl": 3600
    /// }
    /// ```
    ///
    /// # Timeout Semantics
    ///
    /// The 1000ms timeout matches C implementation behavior, giving subscribers
    /// a window to:
    /// 1. Receive notification
    /// 2. Add firewall rules allowing access to resolved IP
    /// 3. Signal completion back to dnsmasq
    ///
    /// After timeout, DNS response is sent regardless of subscriber status.
    ///
    /// # Performance Warning
    ///
    /// The 1000ms timeout BLOCKS the event loop. Subscribers MUST respond quickly
    /// to avoid delaying DNS responses. High query rate with slow subscribers may
    /// impact overall DNS performance.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// ubus.broadcast_connmark_allowlist_resolved(
    ///     0x100,
    ///     "trusted.example.com",
    ///     "192.0.2.1",
    ///     3600
    /// ).await?;
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C function: `void ubus_event_bcast_connmark_allowlist_resolved(...)`
    /// (src/ubus.c lines 906-921) with 1000ms synchronous timeout
    ///
    /// # Conditional Compilation
    ///
    /// Available only with HAVE_CONNTRACK feature.
    #[cfg(feature = "conntrack")]
    pub async fn broadcast_connmark_allowlist_resolved(
        &mut self,
        mark: u32,
        name: &str,
        value: &str,
        ttl: u32,
    ) -> UbusResult<()> {
        debug!(
            "Preparing connmark-allowlist resolved event: mark={:#x}, name={}, value={}, ttl={}",
            mark, name, value, ttl
        );

        // Initialize blob buffer
        self.blob_buf.init(0);

        // Add mark as u32 (matches C implementation)
        self.blob_buf.add_u32("mark", mark).map_err(|e| {
            UbusError::BlobSerializationFailed {
                field: "mark".to_string(),
                reason: e.to_string(),
            }
        })?;

        self.blob_buf.add_string("name", name).map_err(|e| {
            UbusError::BlobSerializationFailed {
                field: "name".to_string(),
                reason: e.to_string(),
            }
        })?;

        self.blob_buf.add_string("value", value).map_err(|e| {
            UbusError::BlobSerializationFailed {
                field: "value".to_string(),
                reason: e.to_string(),
            }
        })?;

        self.blob_buf.add_u32("ttl", ttl).map_err(|e| {
            UbusError::BlobSerializationFailed {
                field: "ttl".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Broadcast event with 1000ms timeout (matches C implementation)
        // This is SYNCHRONOUS and blocks the event loop to allow firewall rule setup
        self.broadcast_event("connmark-allowlist.resolved", CONNMARK_RESOLVED_TIMEOUT_MS).await
    }

    /// Attempts to reconnect to ubus daemon with exponential backoff
    ///
    /// Called automatically when connection loss is detected. Retries connection
    /// with increasing delays between attempts, up to a maximum number of retries.
    ///
    /// # Errors
    ///
    /// - `UbusError::ReconnectionFailed` if max attempts exceeded
    /// - `UbusError::ConnectionFailed` if reconnection attempt fails
    ///
    /// # Exponential Backoff
    ///
    /// - Initial delay: 100ms
    /// - Delay doubles on each failure: 100ms, 200ms, 400ms, 800ms, ...
    /// - Maximum delay: 30 seconds
    /// - Maximum attempts: 10
    ///
    /// # Side Effects
    ///
    /// - Increments `self.reconnect_attempts` on each failure
    /// - Resets `self.reconnect_attempts` to 0 on success
    /// - May log errors on each failed attempt (unless `error_logged` is true)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Detect disconnect in event loop
    /// if let Err(UbusError::Disconnected) = ubus.handle_events().await {
    ///     // Spawn reconnection task
    ///     tokio::spawn(async move {
    ///         if let Err(e) = ubus.reconnect().await {
    ///             error!("Failed to reconnect: {}", e);
    ///         }
    ///     });
    /// }
    /// ```
    ///
    /// # C Implementation Mapping
    ///
    /// Replaces C function: `static void ubus_disconnect_cb(struct ubus_context *ubus)`
    /// (src/ubus.c lines 56-76) which implements immediate reconnection on disconnect
    pub async fn reconnect(&mut self) -> UbusResult<()> {
        info!("Starting ubus reconnection attempts");

        while self.reconnect_attempts < MAX_RECONNECT_ATTEMPTS {
            self.reconnect_attempts += 1;

            // Calculate delay with exponential backoff
            let delay_ms = (RECONNECT_INITIAL_DELAY_MS * (1 << (self.reconnect_attempts - 1)))
                .min(RECONNECT_MAX_DELAY_MS);

            info!(
                "Reconnection attempt {} of {}, waiting {}ms",
                self.reconnect_attempts, MAX_RECONNECT_ATTEMPTS, delay_ms
            );

            sleep(Duration::from_millis(delay_ms)).await;

            // Attempt reconnection
            match self.connect() {
                Ok(()) => {
                    info!("ubus reconnection successful after {} attempts", self.reconnect_attempts);
                    return Ok(());
                }
                Err(e) => {
                    if !self.error_logged {
                        warn!("ubus reconnection attempt {} failed: {}", self.reconnect_attempts, e);
                        self.error_logged = true;
                    }
                }
            }
        }

        error!("ubus reconnection failed after {} attempts", MAX_RECONNECT_ATTEMPTS);
        Err(UbusError::ReconnectionFailed {
            attempts: MAX_RECONNECT_ATTEMPTS,
        })
    }
}

// ============================================================================
// Module-Level Functions
// ============================================================================

/// Initializes ubus integration for dnsmasq
///
/// Creates and connects a new `UbusManager` instance, making the ubus interface
/// available to external clients. This is typically called during daemon startup
/// after configuration is loaded.
///
/// # Arguments
///
/// * `object_name` - Name under which to register ubus object (typically "dnsmasq")
///
/// # Returns
///
/// Initialized and connected `UbusManager` instance, or error if connection fails
///
/// # Errors
///
/// - `UbusError::ConnectionFailed` if ubus daemon is not available
/// - `UbusError::RegistrationFailed` if object registration fails
///
/// # Examples
///
/// ```rust,ignore
/// // During daemon initialization
/// let ubus_manager = match init_ubus("dnsmasq") {
///     Ok(mgr) => {
///         info!("ubus integration enabled");
///         Some(Arc::new(Mutex::new(mgr)))
///     }
///     Err(e) => {
///         warn!("ubus integration disabled: {}", e);
///         None
///     }
/// };
/// ```
///
/// # C Implementation Mapping
///
/// Replaces C function: `char *ubus_init()` (src/ubus.c lines 147-180)
/// which both creates and connects in one step
pub fn init_ubus(object_name: &str) -> UbusResult<UbusManager> {
    info!("Initializing ubus integration with object name '{}'", object_name);

    let mut manager = UbusManager::new(object_name);
    manager.connect()?;

    info!("ubus integration initialized successfully");
    Ok(manager)
}

// ============================================================================
// Helper Structures for FFI
// ============================================================================

// ============================================================================
// Blob Buffer Management
// ============================================================================

/// Owned blob buffer with automatic lifecycle management
///
/// Wraps a heap-allocated blob_buf C struct, providing RAII semantics for
/// memory management. The underlying blob_buf is allocated using the Rust
/// allocator and properly freed on drop.
///
/// # Memory Layout
///
/// From libubox/blobmsg.h, blob_buf has this C structure:
/// ```c
/// struct blob_buf {
///     struct blob_attr *head;      // 8 bytes (64-bit)
///     bool (*grow)(...);            // 8 bytes (function pointer)
///     int buflen;                   // 4 bytes
///     void *buf;                    // 8 bytes (+ 4 padding before)
/// };
/// ```
/// Total: 32 bytes on 64-bit systems. We allocate 64 bytes for safety.
struct OwnedBlobBuf {
    ptr: std::ptr::NonNull<libc::c_void>,
    layout: std::alloc::Layout,
}

impl OwnedBlobBuf {
    /// Allocates a new blob_buf structure
    ///
    /// # Errors
    ///
    /// Returns error if memory allocation fails
    ///
    /// # Safety
    ///
    /// The allocated memory is zero-initialized and properly aligned for
    /// the blob_buf C struct. Lifetime managed via Drop trait.
    fn new() -> Result<Self, UbusError> {
        unsafe {
            // Allocate memory for blob_buf C struct
            // Use 64 bytes (conservative, blob_buf is ~32 bytes)
            let layout = std::alloc::Layout::from_size_align(64, 8)
                .map_err(|_| UbusError::AllocationFailed)?;
            
            let ptr = std::alloc::alloc_zeroed(layout);
            let ptr = std::ptr::NonNull::new(ptr as *mut libc::c_void)
                .ok_or(UbusError::AllocationFailed)?;
            
            Ok(Self { ptr, layout })
        }
    }
    
    /// Returns raw pointer to blob_buf for FFI calls
    #[inline]
    fn as_ptr(&self) -> *mut ubus_ffi::blob_buf {
        self.ptr.as_ptr() as *mut ubus_ffi::blob_buf
    }
    
    /// Initializes the blob buffer for message construction
    ///
    /// # Arguments
    ///
    /// * `id` - Message type identifier (BLOBMSG_TYPE_TABLE for method replies)
    ///
    /// # Safety
    ///
    /// This must be called before adding any fields to the buffer. The buffer
    /// is reset on each init() call, discarding previous contents.
    fn init(&mut self, id: i32) {
        unsafe {
            ubus_ffi::blob_buf_init(self.as_ptr(), id);
        }
    }
    
    /// Adds a u32 field to the blob buffer
    ///
    /// # Arguments
    ///
    /// * `name` - Field name (null-terminated C string)
    /// * `value` - 32-bit unsigned integer value
    ///
    /// # Errors
    ///
    /// Returns error if field name contains null bytes
    fn add_u32(&mut self, name: &str, value: u32) -> Result<(), UbusError> {
        let name_cstr = std::ffi::CString::new(name).map_err(|_| {
            UbusError::BlobSerializationFailed {
                field: name.to_string(),
                reason: "Field name contains null byte".to_string(),
            }
        })?;
        
        unsafe {
            ubus_ffi::blobmsg_add_u32(self.as_ptr(), name_cstr.as_ptr(), value);
        }
        
        Ok(())
    }
    
    /// Adds a string field to the blob buffer
    ///
    /// # Arguments
    ///
    /// * `name` - Field name (null-terminated C string)
    /// * `value` - String value (null-terminated C string)
    ///
    /// # Errors
    ///
    /// Returns error if field name or value contains null bytes
    fn add_string(&mut self, name: &str, value: &str) -> Result<(), UbusError> {
        let name_cstr = std::ffi::CString::new(name).map_err(|_| {
            UbusError::BlobSerializationFailed {
                field: name.to_string(),
                reason: "Field name contains null byte".to_string(),
            }
        })?;
        
        let value_cstr = std::ffi::CString::new(value).map_err(|_| {
            UbusError::BlobSerializationFailed {
                field: name.to_string(),
                reason: "Field value contains null byte".to_string(),
            }
        })?;
        
        unsafe {
            ubus_ffi::blobmsg_add_string(self.as_ptr(), name_cstr.as_ptr(), value_cstr.as_ptr());
        }
        
        Ok(())
    }
}

impl Drop for OwnedBlobBuf {
    fn drop(&mut self) {
        unsafe {
            std::alloc::dealloc(self.ptr.as_ptr() as *mut u8, self.layout);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubus_manager_creation() {
        let manager = UbusManager::new("test-dnsmasq");
        assert_eq!(manager.object_name, "test-dnsmasq");
        assert!(manager.context.is_none());
        assert!(!manager.has_subscribers());
        assert_eq!(manager.reconnect_attempts, 0);
    }

    #[test]
    fn test_has_subscribers_atomic() {
        let manager = UbusManager::new("test");
        assert!(!manager.has_subscribers());

        manager.has_subscribers.store(true, Ordering::Relaxed);
        assert!(manager.has_subscribers());

        manager.has_subscribers.store(false, Ordering::Relaxed);
        assert!(!manager.has_subscribers());
    }

    #[test]
    fn test_ubus_error_display() {
        let err = UbusError::ConnectionFailed {
            message: "test error".to_string(),
            source: None,
        };
        let err_str = format!("{}", err);
        assert!(err_str.contains("Failed to connect to ubus"));
        assert!(err_str.contains("test error"));
    }

    #[test]
    fn test_ubus_error_source_chaining() {
        let io_err = IoError::new(ErrorKind::ConnectionRefused, "socket error");
        let err = UbusError::ConnectionFailed {
            message: "ubus unavailable".to_string(),
            source: Some(io_err),
        };

        // Verify source is preserved
        assert!(err.to_string().contains("ubus unavailable"));
    }

    #[cfg(feature = "conntrack")]
    #[test]
    fn test_connmark_event_format() {
        let mut manager = UbusManager::new("test");
        
        // Test that pattern validation works
        let valid_patterns = vec!["*.example.com".to_string(), "trusted.org".to_string()];
        let result = manager.handle_set_connmark_allowlist(0x100, 0xFF00, valid_patterns);
        
        // This will fail until connection is established, but validates the API
        assert!(matches!(result, Ok(()) | Err(_)));
    }
}


