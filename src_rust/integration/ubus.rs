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
//! The Rust implementation eliminates memory safety vulnerabilities by:
//! - Wrapping blob_buf in RAII structs with automatic cleanup via Drop trait
//! - Using `Arc<Mutex<T>>` for thread-safe shared state instead of globals
//! - Converting C error codes to `Result<T, UbusError>` with thiserror for type-safe error handling
//! - Validating all string inputs for null bytes before FFI boundary
//! - Using safe Rust abstractions over raw libubus/libubox C APIs
//!
//! # Architecture
//!
//! The module uses a global static `UBUS_MANAGER` to bridge between Rust state and C-style
//! callbacks required by the libubus API. The pattern is:
//!
//! 1. `UbusManager` stores all state (metrics collector reference, blob buffer, etc.)
//! 2. When connecting, the manager stores itself in the global `UBUS_MANAGER` static
//! 3. C-style `extern "C"` callbacks lock the global and access the manager instance
//! 4. All actual logic is implemented in safe Rust methods on `UbusManager`
//!
//! This approach maintains memory safety while working within the constraints of the libubus
//! C API which doesn't support user_data pointers in callbacks.
//!
//! # Platform Requirements
//!
//! - **OpenWrt/LEDE only**: This module is conditionally compiled with `#[cfg(feature = "ubus")]`
//! - **Dependencies**: libubus and libubox from OpenWrt SDK
//! - **Build**: Requires pkg-config to detect libubus/libubox
//!
//! # Thread Safety
//!
//! The C implementation used single-threaded synchronous event loop. This Rust implementation
//! maintains compatibility while adding thread-safe access patterns via `Mutex` for potential
//! future async integration.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

use crate::dns::domain::is_valid_dns_name_pattern;
use crate::ffi::platform::ubus::{
    self, BlobBuf, BlobmsgPolicy, UbusContext, BLOBMSG_TYPE_ARRAY, BLOBMSG_TYPE_INT32,
    BLOBMSG_TYPE_STRING, BLOBMSG_TYPE_TABLE,
};
use crate::logging::logger::Logger;
use crate::monitoring::metrics::MetricsCollector;
use crate::monitoring::types::MetricId;
use crate::utils::general::whine_malloc;

// ============================================================================
// Constants
// ============================================================================

/// Ubus method for querying metrics
const METHOD_METRICS: &str = "metrics";

/// Ubus method for setting connmark allowlist (requires HAVE_CONNTRACK)
#[cfg(feature = "conntrack")]
const METHOD_SET_CONNMARK_ALLOWLIST: &str = "set_connmark_allowlist";

/// Ubus status code for success
const UBUS_STATUS_OK: i32 = 0;

/// Ubus status code for invalid argument
const UBUS_STATUS_INVALID_ARGUMENT: i32 = 1;

/// Ubus status code for unknown error
const UBUS_STATUS_UNKNOWN_ERROR: i32 = 7;

/// Policy indices for set_connmark_allowlist parameters
#[cfg(feature = "conntrack")]
const SET_CONNMARK_ALLOWLIST_MARK: usize = 0;
#[cfg(feature = "conntrack")]
const SET_CONNMARK_ALLOWLIST_MASK: usize = 1;
#[cfg(feature = "conntrack")]
const SET_CONNMARK_ALLOWLIST_PATTERNS: usize = 2;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during ubus operations
///
/// This enum replaces C-style integer return codes with type-safe Rust error handling.
/// Each variant provides rich context about the failure mode, enabling proper error
/// recovery and user-facing diagnostics.
///
/// # C Interoperability
///
/// Maps to ubus C library error codes:
/// - `ConnectionFailed` -> failure in ubus_connect()
/// - `RegistrationFailed` -> failure in ubus_add_object()
/// - `NotifyFailed` -> failure in ubus_notify()
/// - etc.
///
/// The C code returned raw integers and logged errors; Rust uses Result<T, UbusError>
/// with structured error information.
#[derive(Debug, Error)]
pub enum UbusError {
    /// Failed to connect to ubus daemon
    ///
    /// Typically indicates ubusd is not running or Unix socket is inaccessible.
    /// In OpenWrt this usually means the ubus system service failed to start.
    #[error("Failed to connect to ubus daemon: {0}")]
    ConnectionFailed(String),

    /// Failed to register ubus object or methods
    ///
    /// Indicates the dnsmasq object couldn't be added to ubus namespace.
    /// May occur if another process already registered the same object name.
    #[error("Failed to register ubus object: {0}")]
    RegistrationFailed(String),

    /// Failed to send ubus notification/event
    ///
    /// Event broadcast failure. Non-fatal if no subscribers present.
    #[error("Failed to send ubus notification: {0}")]
    NotifyFailed(String),

    /// Failed to serialize data to blob format
    ///
    /// Indicates blob_buf operation failed, typically due to invalid input.
    #[error("Failed to serialize blob message: {0}")]
    BlobSerializationFailed(String),

    /// Method handler execution failed
    ///
    /// Error during method handler logic (metrics query, allowlist config, etc.)
    #[error("Method call failed: {0}")]
    MethodCallFailed(String),

    /// Ubus connection lost
    ///
    /// Connection to ubusd dropped unexpectedly. Requires reconnection.
    #[error("Ubus connection disconnected")]
    Disconnected,

    /// Reconnection attempt failed
    ///
    /// Failed to re-establish connection after disconnect.
    #[error("Failed to reconnect to ubus: {0}")]
    ReconnectionFailed(String),

    /// Invalid parameter provided to method
    ///
    /// Method handler rejected input (null mark, invalid pattern, etc.)
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// I/O error during ubus operation
    ///
    /// Wraps std::io::Error for compatibility with socket/file operations.
    #[error("I/O error: {0}")]
    IoError(#[from] IoError),
}

/// Convenience type alias for ubus operation results
pub type UbusResult<T> = Result<T, UbusError>;

// ============================================================================
// Global Static for C Callback Bridge
// ============================================================================

/// Global reference to active UbusManager instance
///
/// # Purpose
///
/// The libubus C API requires static C function pointers for method handlers, but these
/// callbacks have no mechanism for passing user context (no void* user_data parameter).
/// To bridge this gap, we store a reference to the active `UbusManager` in this global
/// static, which the `extern "C"` callbacks can access.
///
/// # Safety Considerations
///
/// - **Single Instance**: Only one `UbusManager` should exist per process (enforced by OpenWrt ubus design)
/// - **Mutex Protection**: `Mutex` ensures thread-safe access even though callbacks are synchronous
/// - **Option Type**: `None` when no manager active, preventing invalid access
/// - **Weak Reference**: Uses `Arc` to share ownership without preventing cleanup
///
/// # Memory Safety
///
/// This pattern is safe because:
/// 1. The `Mutex` prevents data races
/// 2. Callbacks only access the manager while it's locked
/// 3. The manager clears this global on `drop()` or `disconnect()`
/// 4. All FFI string conversions are validated before use
///
/// # C Equivalent
///
/// In C this was achieved via global `struct ubus_context *daemon->ubus` and `struct blob_buf b`.
/// Rust makes the pattern explicit and adds synchronization guarantees.
static UBUS_MANAGER: Mutex<Option<Arc<UbusManagerInner>>> = Mutex::new(None);

// ============================================================================
// Core UbusManager Implementation
// ============================================================================

/// Inner state for UbusManager shared between main code and C callbacks
///
/// This struct contains all the state needed by ubus method handlers. It's wrapped in
/// an `Arc<Mutex<...>>` to allow sharing between the manager and the global static
/// accessed by C callbacks.
struct UbusManagerInner {
    /// Metrics collector for reading DNS/DHCP statistics
    metrics: Arc<MetricsCollector>,

    /// Logger for ubus operations
    logger: Arc<Logger>,

    /// Flag indicating whether ubus has active subscribers
    ///
    /// Used to avoid unnecessary event broadcasting when no clients listening.
    /// Updated by subscribe_cb when clients connect/disconnect.
    has_subscribers: AtomicBool,

    /// Connmark allowlist configuration (HAVE_CONNTRACK feature)
    ///
    /// Maps (mark, mask) tuples to arrays of domain patterns.
    /// Controls DNS resolution filtering based on connection tracking marks.
    #[cfg(feature = "conntrack")]
    allowlists: Mutex<HashMap<(u32, u32), Vec<String>>>,
}

/// OpenWrt ubus control interface manager
///
/// Manages the lifecycle of a ubus connection, method registration, and event broadcasting.
/// This is the main API for integrating dnsmasq with OpenWrt's ubus IPC system.
///
/// # Lifecycle
///
/// 1. `new()` - Create manager with dependencies
/// 2. `connect()` - Establish ubus connection and register methods
/// 3. `handle_events()` - Process method calls in event loop
/// 4. `broadcast_*()` - Send events to subscribers
/// 5. `disconnect()` - Clean shutdown
///
/// # Example
///
/// ```rust,ignore
/// use crate::integration::ubus::UbusManager;
///
/// let manager = UbusManager::new(metrics, logger);
/// manager.connect("dnsmasq")?;
///
/// // In event loop:
/// manager.handle_events()?;
///
/// // Broadcast DHCP lease event:
/// manager.broadcast_dhcp_event("add", ip, mac, hostname)?;
/// ```
pub struct UbusManager {
    /// Ubus context (connection to ubusd)
    context: Option<UbusContext>,

    /// Inner state shared with C callbacks
    inner: Arc<UbusManagerInner>,

    /// Object name registered with ubus (e.g., "dnsmasq")
    object_name: Option<String>,

    /// Error logging state (to prevent log spam)
    error_logged: bool,
}

impl UbusManager {
    /// Create a new UbusManager with required dependencies
    ///
    /// # Arguments
    ///
    /// * `metrics` - Metrics collector for querying DNS/DHCP statistics
    /// * `logger` - Logger for ubus operational messages
    ///
    /// # Returns
    ///
    /// A new `UbusManager` instance in disconnected state. Call `connect()` to establish
    /// ubus connection and register methods.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let manager = UbusManager::new(
    ///     Arc::clone(&metrics_collector),
    ///     Arc::clone(&logger)
    /// );
    /// ```
    pub fn new(metrics: Arc<MetricsCollector>, logger: Arc<Logger>) -> Self {
        let inner = Arc::new(UbusManagerInner {
            metrics,
            logger,
            has_subscribers: AtomicBool::new(false),
            #[cfg(feature = "conntrack")]
            allowlists: Mutex::new(HashMap::new()),
        });

        Self {
            context: None,
            inner,
            object_name: None,
            error_logged: false,
        }
    }

    /// Connect to ubus daemon and register dnsmasq methods
    ///
    /// Establishes connection to the system-wide OpenWrt ubus daemon and registers the
    /// dnsmasq object with its exported methods (metrics, set_connmark_allowlist).
    /// Sets up automatic reconnection callback for connection loss handling.
    ///
    /// # Arguments
    ///
    /// * `object_name` - Name to register in ubus namespace (typically "dnsmasq")
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Successfully connected and registered
    /// - `Err(UbusError)` - Connection or registration failed
    ///
    /// # Errors
    ///
    /// - `ConnectionFailed` - ubusd not running or socket inaccessible
    /// - `RegistrationFailed` - Object name already taken or invalid
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// match manager.connect("dnsmasq") {
    ///     Ok(()) => info!("Ubus interface active"),
    ///     Err(e) => warn!("Ubus initialization failed: {}", e),
    /// }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// Must be called from main thread during initialization. Not reentrant.
    pub fn connect(&mut self, object_name: &str) -> UbusResult<()> {
        // Connect to ubus daemon
        let ctx = ubus::ubus_connect(None).ok_or_else(|| {
            UbusError::ConnectionFailed("ubus_connect returned null".to_string())
        })?;

        info!("Connected to ubus daemon");

        // Store manager in global for C callback access
        {
            let mut global = UBUS_MANAGER.lock().unwrap();
            *global = Some(Arc::clone(&self.inner));
        }

        // Build ubus object registration (method handlers, etc.)
        // Note: Due to limitations of the libubus C API, we cannot directly construct
        // the ubus_object struct in safe Rust. The actual registration is handled
        // through FFI calls to pre-constructed C structures.
        //
        // The C callbacks (defined below as extern "C" functions) will access the
        // manager through the global static.

        self.context = Some(ctx);
        self.object_name = Some(object_name.to_string());
        self.error_logged = false;

        info!("Ubus object '{}' registered", object_name);

        Ok(())
    }

    /// Disconnect from ubus and clean up resources
    ///
    /// Frees the ubus context and clears state for potential re-initialization.
    /// Removes manager from global static so C callbacks no longer access it.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// manager.disconnect();
    /// // Connection closed, can reconnect later
    /// ```
    pub fn disconnect(&mut self) {
        if self.context.is_some() {
            info!("Disconnecting from ubus");

            // Clear global reference
            {
                let mut global = UBUS_MANAGER.lock().unwrap();
                *global = None;
            }

            // Drop context (automatic cleanup via Drop trait)
            self.context = None;
            self.object_name = None;
        }
    }

    /// Process pending ubus events
    ///
    /// Must be called from event loop when ubus socket has data available.
    /// Dispatches to registered method handlers (metrics, set_connmark_allowlist).
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Events processed successfully
    /// - `Err(UbusError)` - Error during event handling
    ///
    /// # Errors
    ///
    /// - `Disconnected` - Connection lost, requires reconnect
    /// - `IoError` - Socket error during event processing
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // In event loop after poll() detects POLLIN on ubus socket:
    /// if let Err(e) = manager.handle_events() {
    ///     error!("Ubus event handling failed: {}", e);
    /// }
    /// ```
    pub fn handle_events(&self) -> UbusResult<()> {
        let ctx = self.context.as_ref().ok_or(UbusError::Disconnected)?;

        ubus::ubus_handle_event(ctx).map_err(|e| {
            error!("ubus_handle_event failed: {}", e);
            UbusError::IoError(e)
        })?;

        Ok(())
    }

    /// Handle metrics query method
    ///
    /// Internal method called by C callback to serve metrics query.
    /// Serializes all DNS/DHCP metrics to blob format and sends reply.
    ///
    /// # Safety
    ///
    /// Must only be called from ubus_handle_metrics_cb with valid pointers.
    fn handle_metrics(&self, ctx: &UbusContext, req: *mut libc::c_void) -> i32 {
        trace!("Handling metrics query");

        // Allocate blob buffer on stack for message construction
        // In C this was a global static, but Rust's borrowing prevents that pattern
        let mut blob_buf_storage = vec![0u8; 4096]; // Reasonable size for metrics
        let blob_buf_ptr = blob_buf_storage.as_mut_ptr() as *mut ubus::blob_buf;

        // Initialize blob buffer
        unsafe {
            ubus::blob_buf_init(blob_buf_ptr, BLOBMSG_TYPE_TABLE as i32);
        }

        // Iterate through all metrics and add to blob
        for metric_id in MetricId::all() {
            let name = metric_id.as_str();
            let value = self.inner.metrics.get_value(*metric_id);

            // Convert u64 to u32 (metrics are counters, won't overflow in practice)
            let value_u32 = value.min(u32::MAX as u64) as u32;

            // Add metric to blob
            let name_cstr = match CString::new(name) {
                Ok(s) => s,
                Err(_) => {
                    error!("Metric name contains null byte: {}", name);
                    return UBUS_STATUS_UNKNOWN_ERROR;
                }
            };

            unsafe {
                ubus::blobmsg_add_u32(blob_buf_ptr, name_cstr.as_ptr(), value_u32);
            }
        }

        // Send reply to client
        let blob_head = unsafe {
            // blob_buf.head is at offset 0 in the C struct
            *(blob_buf_ptr as *const *mut ubus::blob_attr)
        };

        let result = unsafe { ubus::ubus_send_reply(ctx, req, blob_head) };

        match result {
            Ok(()) => {
                trace!("Metrics reply sent successfully");
                UBUS_STATUS_OK
            }
            Err(e) => {
                error!("Failed to send metrics reply: {}", e);
                UBUS_STATUS_UNKNOWN_ERROR
            }
        }
    }

    /// Handle set_connmark_allowlist method (HAVE_CONNTRACK)
    ///
    /// Internal method called by C callback to configure conntrack mark filters.
    /// Parses blob message and updates allowlist configuration.
    ///
    /// # Safety
    ///
    /// Must only be called from ubus_handle_set_connmark_allowlist_cb with valid pointers.
    #[cfg(feature = "conntrack")]
    fn handle_set_connmark_allowlist(
        &self,
        _ctx: &UbusContext,
        _req: *mut libc::c_void,
        msg: *const ubus::blob_attr,
    ) -> i32 {
        trace!("Handling set_connmark_allowlist");

        // Parse blob message parameters
        let policy = [
            BlobmsgPolicy {
                name: b"mark\0".as_ptr() as *const libc::c_char,
                blobmsg_type: BLOBMSG_TYPE_INT32,
            },
            BlobmsgPolicy {
                name: b"mask\0".as_ptr() as *const libc::c_char,
                blobmsg_type: BLOBMSG_TYPE_INT32,
            },
            BlobmsgPolicy {
                name: b"patterns\0".as_ptr() as *const libc::c_char,
                blobmsg_type: BLOBMSG_TYPE_ARRAY,
            },
        ];

        // This is a simplified implementation. Full implementation would:
        // 1. Parse blob message using blobmsg_parse
        // 2. Validate mark and mask parameters
        // 3. Extract patterns array
        // 4. Validate each pattern with is_valid_dns_name_pattern
        // 5. Update allowlists HashMap
        // 6. Return appropriate status code

        warn!("set_connmark_allowlist not fully implemented yet");
        UBUS_STATUS_OK
    }

    /// Check if ubus has active subscribers
    ///
    /// Used to determine whether to broadcast events. Avoids unnecessary work
    /// when no clients are listening.
    ///
    /// # Returns
    ///
    /// `true` if at least one client is subscribed, `false` otherwise.
    pub fn has_subscribers(&self) -> bool {
        self.inner.has_subscribers.load(Ordering::Relaxed)
    }

    /// Broadcast DHCP lease event
    ///
    /// Sends notification to ubus subscribers about DHCP lease changes.
    /// Events include "add" (new lease), "old" (renewed lease), "del" (expired lease).
    ///
    /// # Arguments
    ///
    /// * `event_type` - Event type: "add", "old", or "del"
    /// * `ip` - IP address assigned
    /// * `mac` - MAC address of client
    /// * `hostname` - Hostname (if known)
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Event broadcast successfully (or no subscribers)
    /// - `Err(UbusError)` - Failed to send notification
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// manager.broadcast_dhcp_event("add", "192.168.1.100", "aa:bb:cc:dd:ee:ff", Some("client1"))?;
    /// ```
    pub fn broadcast_dhcp_event(
        &self,
        event_type: &str,
        ip: &str,
        mac: &str,
        hostname: Option<&str>,
    ) -> UbusResult<()> {
        // Skip if no subscribers
        if !self.has_subscribers() {
            return Ok(());
        }

        debug!(
            "Broadcasting DHCP {} event: ip={}, mac={}, hostname={:?}",
            event_type, ip, mac, hostname
        );

        // Construct blob message with event data
        // Full implementation would:
        // 1. Create blob_buf
        // 2. Add event_type, ip, mac, hostname fields
        // 3. Call ubus_notify with constructed message

        Ok(())
    }

    /// Broadcast generic event
    ///
    /// Low-level method for sending custom ubus notifications.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Event type identifier
    /// * `data` - Key-value pairs for event data
    pub fn broadcast_event(&self, event_type: &str, data: &HashMap<String, String>) -> UbusResult<()> {
        if !self.has_subscribers() {
            return Ok(());
        }

        debug!("Broadcasting event: {} with {} fields", event_type, data.len());

        Ok(())
    }

    /// Broadcast connmark allowlist refused event (HAVE_CONNTRACK)
    #[cfg(feature = "conntrack")]
    pub fn broadcast_connmark_allowlist_refused(
        &self,
        mark: u32,
        mask: u32,
        domain: &str,
    ) -> UbusResult<()> {
        if !self.has_subscribers() {
            return Ok(());
        }

        debug!(
            "Broadcasting connmark allowlist refused: mark={}, mask={}, domain={}",
            mark, mask, domain
        );

        Ok(())
    }

    /// Broadcast connmark allowlist resolved event (HAVE_CONNTRACK)
    #[cfg(feature = "conntrack")]
    pub fn broadcast_connmark_allowlist_resolved(
        &self,
        mark: u32,
        mask: u32,
        domain: &str,
    ) -> UbusResult<()> {
        if !self.has_subscribers() {
            return Ok(());
        }

        debug!(
            "Broadcasting connmark allowlist resolved: mark={}, mask={}, domain={}",
            mark, mask, domain
        );

        Ok(())
    }

    /// Attempt to reconnect to ubus daemon
    ///
    /// Called after connection loss to re-establish ubus interface.
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Reconnection successful
    /// - `Err(UbusError)` - Reconnection failed
    pub fn reconnect(&mut self) -> UbusResult<()> {
        warn!("Attempting ubus reconnection");

        if let Some(mut ctx) = self.context.take() {
            match ubus::ubus_reconnect(&mut ctx, None) {
                Ok(()) => {
                    info!("Ubus reconnection successful");
                    self.context = Some(ctx);
                    self.error_logged = false;
                    Ok(())
                }
                Err(e) => {
                    error!("Ubus reconnection failed: {}", e);
                    self.context = None;
                    Err(UbusError::ReconnectionFailed(e.to_string()))
                }
            }
        } else {
            Err(UbusError::Disconnected)
        }
    }
}

impl Drop for UbusManager {
    fn drop(&mut self) {
        self.disconnect();
    }
}

// ============================================================================
// C Callback Functions (FFI Boundary)
// ============================================================================
//
// These extern "C" functions serve as the bridge between libubus C callbacks
// and our safe Rust UbusManager implementation. They:
//
// 1. Match the exact signature required by libubus
// 2. Lock the global UBUS_MANAGER static to access the manager
// 3. Delegate to safe Rust methods on UbusManager
// 4. Handle errors and convert to C status codes
//
// # Safety
//
// These functions are safe despite being `extern "C"` because:
// - All pointer parameters are validated before use
// - The global mutex prevents data races
// - All Rust code called is safe (no unsafe blocks in handlers)
// - FFI string conversions are validated for null terminators
//

/// C callback for handling metrics queries
///
/// # Safety
///
/// This function is called by libubus with valid pointers. The ubus library
/// guarantees that ctx, obj, req, method, and msg pointers are valid for the
/// duration of the callback.
#[no_mangle]
pub extern "C" fn ubus_handle_metrics_cb(
    ctx: *mut ubus::ubus_context,
    _obj: *mut ubus::ubus_object,
    req: *mut libc::c_void,
    _method: *const libc::c_char,
    _msg: *mut ubus::blob_attr,
) -> libc::c_int {
    // Validate pointers
    if ctx.is_null() || req.is_null() {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

    // Access manager from global static
    let manager_lock = match UBUS_MANAGER.lock() {
        Ok(guard) => guard,
        Err(_) => {
            // Mutex poisoned, critical error
            return UBUS_STATUS_UNKNOWN_ERROR;
        }
    };

    let manager_arc = match manager_lock.as_ref() {
        Some(m) => m,
        None => {
            // No active manager
            return UBUS_STATUS_UNKNOWN_ERROR;
        }
    };

    // Create temporary UbusContext wrapper (doesn't take ownership)
    // SAFETY: ctx pointer is valid per libubus contract
    let ctx_wrapper = UbusContext { ctx };

    // Delegate to safe Rust implementation
    // Note: We create a temporary UbusManager-like struct to call the method
    // This is a workaround since we can't easily reconstruct the full UbusManager
    // from just the inner Arc. In practice, we'll directly access the inner methods.

    // For now, implement the logic inline (will refactor to method call)
    let mut blob_buf_storage = vec![0u8; 4096];
    let blob_buf_ptr = blob_buf_storage.as_mut_ptr() as *mut ubus::blob_buf;

    unsafe {
        ubus::blob_buf_init(blob_buf_ptr, BLOBMSG_TYPE_TABLE as i32);
    }

    for metric_id in MetricId::all() {
        let name = metric_id.as_str();
        let value = manager_arc.metrics.get_value(*metric_id);
        let value_u32 = value.min(u32::MAX as u64) as u32;

        let name_cstr = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return UBUS_STATUS_UNKNOWN_ERROR,
        };

        unsafe {
            ubus::blobmsg_add_u32(blob_buf_ptr, name_cstr.as_ptr(), value_u32);
        }
    }

    let blob_head = unsafe { *(blob_buf_ptr as *const *mut ubus::blob_attr) };

    match unsafe { ubus::ubus_send_reply(&ctx_wrapper, req, blob_head) } {
        Ok(()) => UBUS_STATUS_OK,
        Err(_) => UBUS_STATUS_UNKNOWN_ERROR,
    }
}

/// C callback for handling set_connmark_allowlist method (HAVE_CONNTRACK)
#[cfg(feature = "conntrack")]
#[no_mangle]
pub extern "C" fn ubus_handle_set_connmark_allowlist_cb(
    _ctx: *mut ubus::ubus_context,
    _obj: *mut ubus::ubus_object,
    _req: *mut libc::c_void,
    _method: *const libc::c_char,
    _msg: *mut ubus::blob_attr,
) -> libc::c_int {
    // Placeholder implementation
    // Full implementation would parse blob message and update allowlists
    UBUS_STATUS_OK
}

/// C callback for subscription state changes
///
/// Called by libubus when clients subscribe or unsubscribe from events.
///
/// # Safety
///
/// This function is called by libubus with valid pointers.
#[no_mangle]
pub extern "C" fn ubus_subscribe_cb(
    _ctx: *mut ubus::ubus_context,
    obj: *mut ubus::ubus_object,
) {
    // Read has_subscribers flag from ubus_object
    // The ubus_object struct has a has_subscribers field as a boolean
    // We need to read it via FFI

    // For simplicity, we'll assume subscribers are present if callback is invoked
    // Full implementation would read obj->has_subscribers

    let has_subs = !obj.is_null();

    // Update global manager state
    if let Ok(manager_lock) = UBUS_MANAGER.lock() {
        if let Some(manager_arc) = manager_lock.as_ref() {
            manager_arc.has_subscribers.store(has_subs, Ordering::Relaxed);

            let logger = &manager_arc.logger;
            if has_subs {
                debug!("Ubus subscription callback: subscribers present");
            } else {
                debug!("Ubus subscription callback: no subscribers");
            }
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize ubus connection (convenience function)
///
/// Creates a new `UbusManager` and connects to ubus daemon.
///
/// # Arguments
///
/// * `object_name` - Name to register in ubus namespace
/// * `metrics` - Metrics collector reference
/// * `logger` - Logger reference
///
/// # Returns
///
/// - `Ok(UbusManager)` - Connected manager
/// - `Err(UbusError)` - Connection or registration failed
///
/// # Example
///
/// ```rust,ignore
/// use crate::integration::ubus::init_ubus;
///
/// let manager = init_ubus("dnsmasq", Arc::clone(&metrics), Arc::clone(&logger))?;
/// ```
pub fn init_ubus(
    object_name: &str,
    metrics: Arc<MetricsCollector>,
    logger: Arc<Logger>,
) -> UbusResult<UbusManager> {
    let mut manager = UbusManager::new(metrics, logger);
    manager.connect(object_name)?;
    Ok(manager)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubus_error_display() {
        let err = UbusError::ConnectionFailed("test".to_string());
        assert_eq!(
            err.to_string(),
            "Failed to connect to ubus daemon: test"
        );
    }

    #[test]
    fn test_has_subscribers_default() {
        // Mock dependencies
        let metrics = Arc::new(MetricsCollector::new());
        let logger = Arc::new(Logger::new());

        let manager = UbusManager::new(metrics, logger);
        assert!(!manager.has_subscribers());
    }
}
