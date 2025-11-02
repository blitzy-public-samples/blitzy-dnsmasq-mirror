/* dnsmasq is Copyright (c) 2000-2022 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file ubus.c
 * @brief OpenWrt ubus control interface for runtime configuration and event broadcasting.
 *
 * DETAILED PURPOSE:
 * This file implements the ubus (micro bus) IPC interface specifically for OpenWrt/LEDE embedded 
 * Linux distributions. It provides lightweight runtime control and monitoring capabilities for 
 * dnsmasq on resource-constrained routers and embedded devices. The ubus interface is functionally 
 * similar to D-Bus (implemented in dbus.c) but uses OpenWrt's lightweight ubus system which has 
 * minimal memory and CPU overhead suitable for embedded systems.
 * 
 * The implementation exports methods under the "dnsmasq" namespace allowing external applications 
 * and the OpenWrt LuCI web interface to query metrics (DNS cache statistics, query counts), 
 * configure connection tracking marks (connmark allowlists for firewall integration), and receive 
 * real-time event notifications for DHCP leases and DNS resolutions. All communication uses OpenWrt's
 * libubox blob_buf binary format for efficient marshaling on memory-constrained devices.
 *
 * KEY RESPONSIBILITIES:
 * - ubus_init() - Establish connection to system-wide ubus daemon and register dnsmasq methods
 * - ubus_handle_metrics() - Serve DNS/DHCP metrics queries via the "metrics" ubus method
 * - ubus_event_bcast() - Broadcast DHCP lease events (add, old, del) to ubus subscribers
 * - ubus_handle_set_connmark_allowlist() - Configure conntrack mark-based DNS resolution filtering (HAVE_CONNTRACK)
 * - set_ubus_listeners() - Register ubus socket file descriptors with dnsmasq's poll() event loop
 * - check_ubus_listeners() - Process ubus events and handle connection errors/reconnection
 *
 * DEPENDENCIES:
 * - dnsmasq.h - struct daemon, my_syslog(), poll_listen(), poll_check(), whine_malloc()
 * - libubus.h - OpenWrt ubus client library (ubus_connect, ubus_add_object, ubus_notify)
 * - libubox - OpenWrt utility library for blob_buf binary serialization
 * - Calls: daemon->metrics[] (metrics.c), daemon->allowlists (conntrack.c)
 * - Called by: main() in dnsmasq.c for initialization, event_loop() for event processing
 *
 * DATA STRUCTURES:
 * - struct blob_buf b (line 23) - Global blob buffer for ubus message serialization
 * - struct ubus_object ubus_object (lines 67-73) - Registered ubus object exposing dnsmasq methods
 * - struct ubus_object_type ubus_object_type (lines 64-65) - Method signature definitions
 * - struct allowlist (dnsmasq.h) - Conntrack mark-based DNS filtering rules
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_UBUS - Required for all code in this file; OpenWrt/LEDE specific feature
 * - HAVE_CONNTRACK - Enables set_connmark_allowlist method and connmark event broadcasts
 * - Requires libubox and libubus packages from OpenWrt SDK
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. All ubus operations execute in main event loop thread.
 * Ubus socket integrated with poll() multiplexing in dnsmasq.c event_loop(). Method handlers 
 * (ubus_handle_*) are synchronous callbacks invoked during ubus_handle_event(). Event broadcasts
 * (ubus_event_bcast*) are non-blocking notifications sent to subscribers if present. Automatic
 * reconnection on connection loss handled by ubus_disconnect_cb() callback.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_UBUS

#include <libubus.h>

static struct blob_buf b;
static int error_logged = 0;

static int ubus_handle_metrics(struct ubus_context *ctx, struct ubus_object *obj,
			       struct ubus_request_data *req, const char *method,
			       struct blob_attr *msg);

#ifdef HAVE_CONNTRACK
enum {
  SET_CONNMARK_ALLOWLIST_MARK,
  SET_CONNMARK_ALLOWLIST_MASK,
  SET_CONNMARK_ALLOWLIST_PATTERNS
};
static const struct blobmsg_policy set_connmark_allowlist_policy[] = {
  [SET_CONNMARK_ALLOWLIST_MARK] = {
    .name = "mark",
    .type = BLOBMSG_TYPE_INT32
  },
  [SET_CONNMARK_ALLOWLIST_MASK] = {
    .name = "mask",
    .type = BLOBMSG_TYPE_INT32
  },
  [SET_CONNMARK_ALLOWLIST_PATTERNS] = {
    .name = "patterns",
    .type = BLOBMSG_TYPE_ARRAY
  }
};
static int ubus_handle_set_connmark_allowlist(struct ubus_context *ctx, struct ubus_object *obj,
					      struct ubus_request_data *req, const char *method,
					      struct blob_attr *msg);
#endif

static void ubus_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj);

static const struct ubus_method ubus_object_methods[] = {
  UBUS_METHOD_NOARG("metrics", ubus_handle_metrics),
#ifdef HAVE_CONNTRACK
  UBUS_METHOD("set_connmark_allowlist", ubus_handle_set_connmark_allowlist, set_connmark_allowlist_policy),
#endif
};

static struct ubus_object_type ubus_object_type =
  UBUS_OBJECT_TYPE("dnsmasq", ubus_object_methods);

static struct ubus_object ubus_object = {
  .name = NULL,
  .type = &ubus_object_type,
  .methods = ubus_object_methods,
  .n_methods = ARRAY_SIZE(ubus_object_methods),
  .subscribe_cb = ubus_subscribe_cb,
};

/**
 * @brief Handle ubus subscription state changes for event notifications.
 *
 * @detailed
 * Callback invoked by ubus library when subscribers attach to or detach from the dnsmasq ubus object.
 * Logs subscription state changes for debugging purposes. Actual event broadcasting checks 
 * obj->has_subscribers flag before sending notifications to avoid unnecessary work.
 *
 * @param ctx Ubus context (unused in this implementation)
 * @param obj Ubus object whose subscription state changed (contains has_subscribers flag)
 *
 * @note
 * Only logs debug message indicating presence or absence of subscribers. Does not track individual
 * subscriber identities or counts beyond binary has_subscribers state.
 *
 * @warning
 * Called from ubus library context; must not perform blocking operations or heavy processing.
 *
 * @see ubus_event_bcast() for event broadcasting that checks has_subscribers
 *
 * EXAMPLE USAGE:
 * @code
 * // Automatically invoked by ubus library on subscription changes
 * // When LuCI web interface subscribes: "UBus subscription callback: 1 subscriber(s)"
 * // When all clients disconnect: "UBus subscription callback: 0 subscriber(s)"
 * @endcode
 *
 * SIDE EFFECTS:
 * Logs to syslog at LOG_DEBUG level. No state modifications.
 *
 * THREAD SAFETY:
 * Called from main event loop thread. Safe as part of single-threaded architecture.
 */
static void ubus_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj)
{
  (void)ctx;

  my_syslog(LOG_DEBUG, _("UBus subscription callback: %s subscriber(s)"), obj->has_subscribers ? "1" : "0");
}

/**
 * @brief Clean up and destroy ubus connection, resetting state for potential re-initialization.
 *
 * @detailed
 * Frees the ubus context and clears daemon->ubus pointer to indicate no active connection. 
 * Additionally resets ubus_object.id and ubus_object_type.id to zero, which is required by 
 * the ubus library to allow re-registration of the same object definitions if dnsmasq reconnects
 * after connection loss or restart.
 *
 * @param ubus Ubus context to destroy (must not be NULL)
 *
 * @note
 * Must be called when ubus connection is lost or during shutdown. Forces clean state for 
 * subsequent ubus_init() calls to succeed without stale object IDs.
 *
 * @warning
 * After this call, daemon->ubus is NULL and all ubus operations will fail safely. Caller must
 * ensure no concurrent access to ubus context during destruction.
 *
 * @see ubus_disconnect_cb() which calls this on connection loss
 * @see ubus_init() which can be called after this to re-establish connection
 *
 * EXAMPLE USAGE:
 * @code
 * struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;
 * if (poll_check(ubus->sock.fd, POLLHUP | POLLERR)) {
 *     my_syslog(LOG_INFO, "Disconnecting from UBus");
 *     ubus_destroy(ubus);
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Frees ubus context memory via ubus_free()
 * - Sets daemon->ubus = NULL
 * - Resets ubus_object.id and ubus_object_type.id to 0
 *
 * THREAD SAFETY:
 * Must be called from main event loop thread only. Not reentrant.
 */
static void ubus_destroy(struct ubus_context *ubus)
{
  ubus_free(ubus);
  daemon->ubus = NULL;
  
  /* Forces re-initialization when we're reusing the same definitions later on. */
  ubus_object.id = 0;
  ubus_object_type.id = 0;
}

/**
 * @brief Handle ubus connection loss by attempting reconnection or cleaning up.
 *
 * @detailed
 * Callback registered with ubus library (ubus->connection_lost) to handle unexpected disconnections
 * from the system ubus daemon. Attempts single reconnection using ubus_reconnect(). If reconnection
 * succeeds, restores full operation. If reconnection fails, logs error and performs complete cleanup
 * via ubus_destroy(), requiring manual restart or external monitoring to re-establish connection.
 *
 * @param ubus Ubus context that lost connection
 *
 * @retval void No return value; errors logged to syslog
 *
 * @note
 * Automatic reconnection is single-attempt only. Does not implement exponential backoff or retry
 * loop to avoid busy-waiting if ubus daemon is permanently unavailable.
 *
 * @warning
 * If reconnection fails, dnsmasq continues operating but ubus control interface becomes unavailable
 * until manual intervention or daemon restart. External monitoring recommended for production.
 *
 * @see ubus_destroy() called on reconnection failure
 * @see ubus_init() where this callback is registered
 *
 * EXAMPLE USAGE:
 * @code
 * // Registered during initialization:
 * ubus->connection_lost = ubus_disconnect_cb;
 * // Automatically invoked by ubus library on connection loss
 * // On success: Connection restored transparently
 * // On failure: "Cannot reconnect to UBus: <error>" logged, daemon->ubus set to NULL
 * @endcode
 *
 * SIDE EFFECTS:
 * - Calls ubus_reconnect() which may block briefly
 * - On failure: logs error, calls ubus_destroy() clearing daemon->ubus
 * - On success: restores connection with no state loss
 *
 * THREAD SAFETY:
 * Invoked from main event loop thread by ubus library. Safe in single-threaded architecture.
 */
static void ubus_disconnect_cb(struct ubus_context *ubus)
{
  int ret;

  ret = ubus_reconnect(ubus, NULL);
  if (ret)
    {
      my_syslog(LOG_ERR, _("Cannot reconnect to UBus: %s"), ubus_strerror(ret));

      ubus_destroy(ubus);
    }
}

/**
 * @brief Initialize ubus connection and register dnsmasq methods for runtime control.
 *
 * @detailed
 * Establishes connection to the system-wide OpenWrt ubus daemon and registers the dnsmasq ubus
 * object with its exported methods (metrics, set_connmark_allowlist). Sets up automatic 
 * reconnection callback for connection loss handling. On success, stores ubus context in 
 * daemon->ubus for subsequent event loop integration. Object name is configurable via 
 * daemon->ubus_name to allow multiple dnsmasq instances or custom naming.
 *
 * @return NULL on success, error string from ubus_strerror() on failure
 * @retval NULL Successfully connected and registered ubus object
 * @retval "Connection failed" or similar Error message from ubus library (do not free)
 *
 * @note
 * Must be called during dnsmasq initialization before entering event loop. Connection uses Unix
 * domain socket at /var/run/ubus/ubus.sock (OpenWrt standard location). Requires ubusd daemon
 * running and accessible.
 *
 * @warning
 * Returns static error string from ubus_strerror() - caller must NOT free returned pointer.
 * If connection fails, daemon->ubus remains NULL and all subsequent ubus operations no-op safely.
 * Does not retry on failure; external process management should restart dnsmasq if ubus is critical.
 *
 * @see set_ubus_listeners() which must be called after this to integrate with poll() loop
 * @see ubus_disconnect_cb() registered as connection_lost callback
 * @see check_ubus_listeners() for event processing
 *
 * EXAMPLE USAGE:
 * @code
 * char *err;
 * if ((err = ubus_init())) {
 *     my_syslog(LOG_WARNING, "UBus initialization failed: %s", err);
 *     // Continue without ubus control interface
 * } else {
 *     my_syslog(LOG_INFO, "UBus interface active");
 *     set_ubus_listeners(); // Register with event loop
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Connects to ubusd via ubus_connect()
 * - Registers dnsmasq object via ubus_add_object()
 * - Sets daemon->ubus pointer to ubus context
 * - Resets error_logged flag to 0
 * - Registers ubus_disconnect_cb as connection_lost handler
 *
 * THREAD SAFETY:
 * Must be called from main thread during initialization only. Not reentrant.
 */
char *ubus_init()
{
  struct ubus_context *ubus = NULL;
  int ret = 0;

  if (!(ubus = ubus_connect(NULL)))
    return NULL;
  
  ubus_object.name = daemon->ubus_name;
  ret = ubus_add_object(ubus, &ubus_object);
  if (ret)
    {
      ubus_destroy(ubus);
      return (char *)ubus_strerror(ret);
    }    
  
  ubus->connection_lost = ubus_disconnect_cb;
  daemon->ubus = ubus;
  error_logged = 0;

  return NULL;
}

/**
 * @brief Register ubus socket file descriptor with dnsmasq's poll() event loop.
 *
 * @detailed
 * Adds the ubus socket file descriptor to the set of file descriptors monitored by dnsmasq's
 * main event loop poll() call. Monitors POLLIN (data ready to read), POLLERR (error condition),
 * and POLLHUP (connection closed) events. Must be called after successful ubus_init() and 
 * whenever poll registration needs refreshing (typically once per event loop iteration before poll()).
 *
 * @note
 * Safe to call if no ubus connection exists (daemon->ubus == NULL); logs error once and returns.
 * Error logging uses error_logged flag to prevent log spam on repeated calls without connection.
 *
 * @warning
 * Must be called before each poll() invocation to ensure ubus socket is monitored. Does not
 * validate ubus context beyond NULL check; assumes valid context if non-NULL.
 *
 * @see poll_listen() in poll.c which registers file descriptors for monitoring
 * @see check_ubus_listeners() which handles events detected by poll()
 * @see ubus_init() which must be called first to establish connection
 *
 * EXAMPLE USAGE:
 * @code
 * // In event loop before poll():
 * set_ubus_listeners();
 * set_dns_listeners();
 * set_dhcp_listeners();
 * poll(fds, nfds, timeout);
 * check_ubus_listeners(); // Process any ubus events
 * @endcode
 *
 * SIDE EFFECTS:
 * - Calls poll_listen() three times to register ubus->sock.fd for POLLIN, POLLERR, POLLHUP
 * - May log "Cannot set UBus listeners: no connection" once if daemon->ubus is NULL
 * - Sets error_logged flag to prevent repeated error messages
 *
 * THREAD SAFETY:
 * Must be called from main event loop thread only. Not reentrant.
 */
void set_ubus_listeners()
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;
  if (!ubus)
    {
      if (!error_logged)
        {
          my_syslog(LOG_ERR, _("Cannot set UBus listeners: no connection"));
          error_logged = 1;
        }
      return;
    }

  error_logged = 0;

  poll_listen(ubus->sock.fd, POLLIN);
  poll_listen(ubus->sock.fd, POLLERR);
  poll_listen(ubus->sock.fd, POLLHUP);
}

/**
 * @brief Process pending ubus events and handle connection state changes.
 *
 * @detailed
 * Checks if ubus socket has pending data or error conditions detected by poll(), then dispatches
 * events via ubus_handle_event() which invokes registered method handlers. Handles connection
 * errors (POLLHUP, POLLERR) by logging disconnection and calling ubus_destroy() for cleanup.
 * Must be called after poll() returns to process any ubus activity detected during event loop iteration.
 *
 * @note
 * Safe to call if no ubus connection exists (daemon->ubus == NULL); logs error once and returns.
 * POLLIN events trigger method handler callbacks (ubus_handle_metrics, ubus_handle_set_connmark_allowlist).
 * Error logging suppressed after first occurrence until connection restored.
 *
 * @warning
 * Connection loss (POLLHUP/POLLERR) destroys ubus context immediately. Subsequent ubus operations
 * become no-ops until explicit reconnection or daemon restart. Does not automatically reconnect
 * from this function; reconnection attempts occur only in ubus_disconnect_cb().
 *
 * @see poll_check() in poll.c which tests if specific events occurred
 * @see ubus_handle_event() from libubus which dispatches to method handlers
 * @see ubus_destroy() called on connection loss
 * @see set_ubus_listeners() which must be called before poll()
 *
 * EXAMPLE USAGE:
 * @code
 * // In event loop after poll() returns:
 * poll(fds, nfds, timeout);
 * check_ubus_listeners(); // Process ubus method calls
 * check_dns_listeners();   // Process DNS queries
 * check_dhcp_listeners();  // Process DHCP requests
 * @endcode
 *
 * SIDE EFFECTS:
 * - Calls ubus_handle_event() which may invoke method handlers synchronously
 * - Method handlers may modify daemon state (metrics read, connmark allowlist modified)
 * - On POLLHUP/POLLERR: logs disconnection, calls ubus_destroy(), sets daemon->ubus = NULL
 * - Updates error_logged flag
 *
 * THREAD SAFETY:
 * Must be called from main event loop thread only. Method handlers execute synchronously.
 */
void check_ubus_listeners()
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;
  if (!ubus)
    {
      if (!error_logged)
        {
          my_syslog(LOG_ERR, _("Cannot poll UBus listeners: no connection"));
          error_logged = 1;
        }
      return;
    }
  
  error_logged = 0;

  if (poll_check(ubus->sock.fd, POLLIN))
    ubus_handle_event(ubus);
  
  if (poll_check(ubus->sock.fd, POLLHUP | POLLERR))
    {
      my_syslog(LOG_INFO, _("Disconnecting from UBus"));

      ubus_destroy(ubus);
    }
}

#define CHECK(stmt) \
  do { \
    int e = (stmt); \
    if (e) \
      { \
	my_syslog(LOG_ERR, _("UBus command failed: %d (%s)"), e, #stmt); \
	return (UBUS_STATUS_UNKNOWN_ERROR); \
      } \
  } while (0)

/**
 * @brief Handle ubus "metrics" method call to query DNS and DHCP statistics.
 *
 * @detailed
 * Ubus method handler that serializes all dnsmasq metrics (daemon->metrics[] array) into a blob_buf
 * table and returns to caller via ubus_send_reply(). Metrics include DNS queries served, cache hits/misses,
 * DHCP leases allocated, and other counters tracked by metrics.c. Data returned as key-value pairs where
 * keys are metric names from get_metric_name() and values are 32-bit unsigned integers.
 *
 * @param ctx Ubus context for sending reply
 * @param obj Ubus object being invoked (unused, suppressed warning)
 * @param req Request data structure containing client information for reply routing
 * @param method Method name string "metrics" (unused, suppressed warning)
 * @param msg Blob message from client (unused, no parameters expected, suppressed warning)
 *
 * @return UBUS_STATUS_OK on success, UBUS_STATUS_UNKNOWN_ERROR if any blob operation fails
 * @retval UBUS_STATUS_OK Metrics successfully serialized and sent to client
 * @retval UBUS_STATUS_UNKNOWN_ERROR Blob buffer initialization or message construction failed
 *
 * @note
 * Iterates through all metrics up to __METRIC_MAX (defined in metrics.h). CHECK macro logs errors
 * and returns UBUS_STATUS_UNKNOWN_ERROR on any failure. Method requires no input parameters; msg
 * parameter ignored.
 *
 * @warning
 * Uses global blob_buf b for message construction; not reentrant if called concurrently (safe in
 * single-threaded event loop). Metric values are instantaneous snapshots, not atomic with respect
 * to ongoing operations.
 *
 * @see get_metric_name() in metrics.c for metric name strings
 * @see daemon->metrics[] in struct daemon for counter values
 *
 * EXAMPLE USAGE:
 * @code
 * // Called via ubus command line:
 * // ubus call dnsmasq metrics
 * // Returns: {"queries": 12345, "queries_forwarded": 9876, "cache_hits": 5432, ...}
 * @endcode
 *
 * SIDE EFFECTS:
 * - Initializes and populates global blob_buf b
 * - Reads all values from daemon->metrics[] array (read-only access)
 * - Sends blob message to ubus client via ubus_send_reply()
 * - Logs errors if blob operations fail
 *
 * THREAD SAFETY:
 * Must be called from main event loop thread. Not reentrant due to global blob_buf usage.
 */
static int ubus_handle_metrics(struct ubus_context *ctx, struct ubus_object *obj,
			       struct ubus_request_data *req, const char *method,
			       struct blob_attr *msg)
{
  int i;

  (void)obj;
  (void)method;
  (void)msg;

  CHECK(blob_buf_init(&b, BLOBMSG_TYPE_TABLE));

  for (i=0; i < __METRIC_MAX; i++)
    CHECK(blobmsg_add_u32(&b, get_metric_name(i), daemon->metrics[i]));
  
  CHECK(ubus_send_reply(ctx, req, b.head));
  return UBUS_STATUS_OK;
}

#ifdef HAVE_CONNTRACK
/**
 * @brief Handle ubus "set_connmark_allowlist" method to configure connection tracking mark filters.
 *
 * @detailed
 * Ubus method handler that configures DNS resolution filtering based on Linux connection tracking (conntrack)
 * marks. Allows specifying which DNS domain patterns are permitted to be resolved for connections marked with
 * specific conntrack mark/mask combinations. Integrates with netfilter conntrack to enforce firewall-level
 * DNS resolution policies. Parses blob message containing mark (required), mask (optional, default 0xFFFFFFFF),
 * and patterns array (domain wildcards). Updates daemon->allowlists linked list, replacing existing entry with
 * same mark/mask if present. Empty patterns array removes existing allowlist entry.
 *
 * @param ctx Ubus context (unused but required by signature)
 * @param obj Ubus object being invoked (unused but required by signature)  
 * @param req Request data (unused but required by signature)
 * @param method Method name string "set_connmark_allowlist" (unused but required by signature)
 * @param msg Blob message containing parameters: mark (u32), mask (u32 optional), patterns (array of strings)
 *
 * @return UBUS_STATUS_OK, UBUS_STATUS_INVALID_ARGUMENT, or UBUS_STATUS_UNKNOWN_ERROR
 * @retval UBUS_STATUS_OK Allowlist successfully configured or removed
 * @retval UBUS_STATUS_INVALID_ARGUMENT Missing mark, invalid mask, invalid domain pattern, or parse failure
 * @retval UBUS_STATUS_UNKNOWN_ERROR Memory allocation failure during pattern or allowlist creation
 *
 * @note
 * Domain patterns validated via is_valid_dns_name_pattern(); wildcard "*" accepts all domains. Mark must be
 * non-zero. Mask bits must cover all set bits in mark ((mark & ~mask) == 0). Removes allowlist entry if
 * patterns array empty or absent after mark/mask validation.
 *
 * @warning
 * Memory allocation failures cause partial cleanup and return UBUS_STATUS_UNKNOWN_ERROR; existing allowlist
 * entry may be removed even on failure. Caller must handle errors appropriately. Pattern validation does not
 * guarantee semantic correctness of firewall rules.
 *
 * @see daemon->allowlists in dnsmasq.h for allowlist linked list structure
 * @see is_valid_dns_name_pattern() for domain pattern validation
 * @see ubus_event_bcast_connmark_allowlist_refused() for event broadcast on blocked resolution
 * @see ubus_event_bcast_connmark_allowlist_resolved() for event broadcast on allowed resolution
 *
 * EXAMPLE USAGE:
 * @code
 * // Via ubus command line:
 * // ubus call dnsmasq set_connmark_allowlist '{"mark":100, "mask":255, "patterns":["*.example.com","safe.org"]}'
 * // Allows marked connections (mark 100) to resolve only *.example.com and safe.org
 * // Empty patterns removes allowlist:
 * // ubus call dnsmasq set_connmark_allowlist '{"mark":100, "mask":255}'
 * @endcode
 *
 * SIDE EFFECTS:
 * - Parses blob message parameters via blobmsg_parse()
 * - Searches and potentially removes existing allowlist entry with matching mark/mask
 * - Allocates memory for new allowlist entry and pattern strings via whine_malloc()
 * - Modifies daemon->allowlists linked list (prepends new entry or removes matching entry)
 * - On memory allocation failure: partial cleanup of allocated patterns
 *
 * THREAD SAFETY:
 * Must be called from main event loop thread. Not reentrant. Modifies global daemon state.
 */
static int ubus_handle_set_connmark_allowlist(struct ubus_context *ctx, struct ubus_object *obj,
					      struct ubus_request_data *req, const char *method,
					      struct blob_attr *msg)
{
  const struct blobmsg_policy *policy = set_connmark_allowlist_policy;
  size_t policy_len = countof(set_connmark_allowlist_policy);
  struct allowlist *allowlists = NULL, **allowlists_pos;
  char **patterns = NULL, **patterns_pos;
  u32 mark, mask = UINT32_MAX;
  size_t num_patterns = 0;
  struct blob_attr *tb[policy_len];
  struct blob_attr *attr;
  
  if (blobmsg_parse(policy, policy_len, tb, blob_data(msg), blob_len(msg)))
    return UBUS_STATUS_INVALID_ARGUMENT;
  
  if (!tb[SET_CONNMARK_ALLOWLIST_MARK])
    return UBUS_STATUS_INVALID_ARGUMENT;
  mark = blobmsg_get_u32(tb[SET_CONNMARK_ALLOWLIST_MARK]);
  if (!mark)
    return UBUS_STATUS_INVALID_ARGUMENT;
  
  if (tb[SET_CONNMARK_ALLOWLIST_MASK])
    {
      mask = blobmsg_get_u32(tb[SET_CONNMARK_ALLOWLIST_MASK]);
      if (!mask || (mark & ~mask))
	return UBUS_STATUS_INVALID_ARGUMENT;
    }
  
  if (tb[SET_CONNMARK_ALLOWLIST_PATTERNS])
    {
      struct blob_attr *head = blobmsg_data(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      size_t len = blobmsg_data_len(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      __blob_for_each_attr(attr, head, len)
	{
	  char *pattern;
	  if (blob_id(attr) != BLOBMSG_TYPE_STRING)
	    return UBUS_STATUS_INVALID_ARGUMENT;
	  if (!(pattern = blobmsg_get_string(attr)))
	    return UBUS_STATUS_INVALID_ARGUMENT;
	  if (strcmp(pattern, "*") && !is_valid_dns_name_pattern(pattern))
	    return UBUS_STATUS_INVALID_ARGUMENT;
	  num_patterns++;
	}
    }
  
  for (allowlists_pos = &daemon->allowlists; *allowlists_pos; allowlists_pos = &(*allowlists_pos)->next)
    if ((*allowlists_pos)->mark == mark && (*allowlists_pos)->mask == mask)
      {
	struct allowlist *allowlists_next = (*allowlists_pos)->next;
	for (patterns_pos = (*allowlists_pos)->patterns; *patterns_pos; patterns_pos++)
	  {
	    free(*patterns_pos);
	    *patterns_pos = NULL;
	  }
	free((*allowlists_pos)->patterns);
	(*allowlists_pos)->patterns = NULL;
	free(*allowlists_pos);
	*allowlists_pos = allowlists_next;
	break;
      }
  
  if (!num_patterns)
    return UBUS_STATUS_OK;
  
  patterns = whine_malloc((num_patterns + 1) * sizeof(char *));
  if (!patterns)
    goto fail;
  patterns_pos = patterns;
  if (tb[SET_CONNMARK_ALLOWLIST_PATTERNS])
    {
      struct blob_attr *head = blobmsg_data(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      size_t len = blobmsg_data_len(tb[SET_CONNMARK_ALLOWLIST_PATTERNS]);
      __blob_for_each_attr(attr, head, len)
	{
	  char *pattern;
	  if (!(pattern = blobmsg_get_string(attr)))
	    goto fail;
	  if (!(*patterns_pos = whine_malloc(strlen(pattern) + 1)))
	    goto fail;
	  strcpy(*patterns_pos++, pattern);
	}
    }
  
  allowlists = whine_malloc(sizeof(struct allowlist));
  if (!allowlists)
    goto fail;
  memset(allowlists, 0, sizeof(struct allowlist));
  allowlists->mark = mark;
  allowlists->mask = mask;
  allowlists->patterns = patterns;
  allowlists->next = daemon->allowlists;
  daemon->allowlists = allowlists;
  return UBUS_STATUS_OK;
  
fail:
  if (patterns)
    {
      for (patterns_pos = patterns; *patterns_pos; patterns_pos++)
	{
	  free(*patterns_pos);
	  *patterns_pos = NULL;
	}
      free(patterns);
      patterns = NULL;
    }
  if (allowlists)
    {
      free(allowlists);
      allowlists = NULL;
    }
  return UBUS_STATUS_UNKNOWN_ERROR;
}
#endif

#undef CHECK

#define CHECK(stmt) \
  do { \
    int e = (stmt); \
    if (e) \
      { \
	my_syslog(LOG_ERR, _("UBus command failed: %d (%s)"), e, #stmt); \
	return; \
      } \
  } while (0)

/**
 * @brief Broadcast DHCP lease or DNS resolution events to ubus subscribers.
 *
 * @detailed
 * Sends asynchronous notification to all ubus subscribers when DHCP leases change or DNS resolutions occur.
 * Constructs blob message containing MAC address, IP address, hostname, and interface name (all optional
 * based on NULL parameters). Event type distinguishes between "dhcp.add" (new lease), "dhcp.old" (renewed
 * lease), "dhcp.del" (expired/released lease), and custom event types. Only sends if subscribers present
 * (ubus_object.has_subscribers == true) to avoid unnecessary message construction overhead.
 *
 * @param type Event type string (e.g., "dhcp.add", "dhcp.old", "dhcp.del")
 * @param mac Client MAC address string (optional, NULL if not applicable)
 * @param ip Client IP address string (optional, NULL if not applicable)
 * @param name Hostname string (optional, NULL if not applicable)
 * @param interface Network interface name string (optional, NULL if not applicable)
 *
 * @note
 * All string parameters are optional; only non-NULL values included in blob message. CHECK macro logs
 * errors on blob operation failures but cannot return error to caller (void function). Event notifications
 * are fire-and-forget with -1 timeout (asynchronous, no acknowledgment required).
 *
 * @warning
 * Uses global blob_buf b for message construction; not reentrant. Safe in single-threaded architecture.
 * Returns silently if no ubus connection (daemon->ubus == NULL) or no subscribers, which is normal during
 * initialization or if no monitoring clients active.
 *
 * @see ubus_object.has_subscribers checked to optimize for no-subscriber case
 * @see CHECK macro which logs errors on blob operations
 * @see ubus_notify() from libubus which sends notification to subscribers
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from DHCP lease code when new lease assigned:
 * ubus_event_bcast("dhcp.add", "aa:bb:cc:dd:ee:ff", "192.168.1.100", "laptop", "eth0");
 * // Subscribers receive: {"mac":"aa:bb:cc:dd:ee:ff", "ip":"192.168.1.100", 
 * //                       "name":"laptop", "interface":"eth0"}
 * @endcode
 *
 * SIDE EFFECTS:
 * - Initializes and populates global blob_buf b
 * - Sends ubus notification to all subscribers via ubus_notify()
 * - Logs errors if blob operations fail (via CHECK macro)
 * - No state modification; read-only operation on daemon->ubus
 *
 * THREAD SAFETY:
 * Must be called from main event loop thread. Not reentrant due to global blob_buf usage.
 */
void ubus_event_bcast(const char *type, const char *mac, const char *ip, const char *name, const char *interface)
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;

  if (!ubus || !ubus_object.has_subscribers)
    return;

  CHECK(blob_buf_init(&b, BLOBMSG_TYPE_TABLE));
  if (mac)
    CHECK(blobmsg_add_string(&b, "mac", mac));
  if (ip)
    CHECK(blobmsg_add_string(&b, "ip", ip));
  if (name)
    CHECK(blobmsg_add_string(&b, "name", name));
  if (interface)
    CHECK(blobmsg_add_string(&b, "interface", interface));
  
  CHECK(ubus_notify(ubus, &ubus_object, type, b.head, -1));
}

#ifdef HAVE_CONNTRACK
/**
 * @brief Broadcast event when DNS resolution refused due to connmark allowlist policy.
 *
 * @detailed
 * Sends ubus notification "connmark-allowlist.refused" to subscribers when a DNS query is blocked because
 * the querying connection's conntrack mark does not match any allowlist or the requested domain does not
 * match allowlist patterns. Provides visibility into firewall-enforced DNS filtering for monitoring and
 * debugging. Event includes the conntrack mark value that caused the refusal and the denied domain name.
 *
 * @param mark Connection tracking mark value (u32) that triggered the refusal
 * @param name Domain name string that was denied resolution
 *
 * @note
 * Only sends if subscribers present (ubus_object.has_subscribers == true). Notification is fire-and-forget
 * with -1 timeout. CHECK macro logs errors on blob operation failures. Returns silently if no ubus
 * connection or no subscribers.
 *
 * @warning
 * Uses global blob_buf b; not reentrant. Safe in single-threaded event loop. High query rate may cause
 * log spam if many queries refused; subscribers should implement rate limiting or filtering.
 *
 * @see ubus_handle_set_connmark_allowlist() which configures the allowlist policies
 * @see ubus_event_bcast_connmark_allowlist_resolved() for successful resolution events
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from DNS forwarding code when query blocked by connmark allowlist:
 * if (connection_mark_not_allowed(mark, domain)) {
 *     ubus_event_bcast_connmark_allowlist_refused(mark, "blocked.example.com");
 *     return; // Refuse to resolve
 * }
 * // Subscribers receive: {"mark":100, "name":"blocked.example.com"}
 * @endcode
 *
 * SIDE EFFECTS:
 * - Initializes and populates global blob_buf b with mark and name fields
 * - Sends ubus notification "connmark-allowlist.refused" to subscribers via ubus_notify()
 * - Logs errors if blob operations fail (via CHECK macro)
 *
 * THREAD SAFETY:
 * Must be called from main event loop thread. Not reentrant due to global blob_buf usage.
 */
void ubus_event_bcast_connmark_allowlist_refused(u32 mark, const char *name)
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;

  if (!ubus || !ubus_object.has_subscribers)
    return;

  CHECK(blob_buf_init(&b, 0));
  CHECK(blobmsg_add_u32(&b, "mark", mark));
  CHECK(blobmsg_add_string(&b, "name", name));
  
  CHECK(ubus_notify(ubus, &ubus_object, "connmark-allowlist.refused", b.head, -1));
}

/**
 * @brief Broadcast event when DNS resolution succeeds after connmark allowlist validation.
 *
 * @detailed
 * Sends ubus notification "connmark-allowlist.resolved" to subscribers when a DNS query is successfully
 * resolved after passing connmark allowlist policy checks. Enables external firewall or routing systems
 * to dynamically configure rules based on resolved IP addresses. Event includes conntrack mark, original
 * domain name, resolved IP address string, and TTL. Notification uses 1000ms timeout (synchronous) to allow
 * subscribers to configure firewall rules before DNS response returned to client, ensuring traffic
 * correctly routed based on mark.
 *
 * @param mark Connection tracking mark value (u32) associated with the allowed resolution
 * @param name Domain name string that was successfully resolved
 * @param value Resolved IP address string (A or AAAA record value)
 * @param ttl Time-to-live value (u32) from DNS response, indicating cache validity duration
 *
 * @note
 * Uses 1000ms timeout (synchronous notification) unlike other events, allowing subscribers to perform
 * setup before response sent. Only sends if subscribers present. Returns silently if no connection or
 * no subscribers. CHECK macro logs errors on blob operation failures.
 *
 * @warning
 * 1000ms timeout blocks event loop; subscribers MUST respond quickly to avoid delaying DNS responses.
 * Uses global blob_buf b; not reentrant. High query rate may impact performance if subscribers slow.
 * Subscribers should implement efficient rule configuration to minimize latency.
 *
 * @see ubus_handle_set_connmark_allowlist() which configures allowlist policies
 * @see ubus_event_bcast_connmark_allowlist_refused() for blocked resolution events
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from DNS forwarding code after successful resolution passing allowlist:
 * if (connection_mark_allowed(mark, domain) && resolution_success) {
 *     ubus_event_bcast_connmark_allowlist_resolved(mark, "allowed.example.com", "192.0.2.1", 3600);
 *     // Subscribers configure firewall rules for 192.0.2.1 with mark 100
 *     return_dns_response_to_client();
 * }
 * // Subscribers receive: {"mark":100, "name":"allowed.example.com", "value":"192.0.2.1", "ttl":3600}
 * @endcode
 *
 * SIDE EFFECTS:
 * - Initializes and populates global blob_buf b with mark, name, value, ttl fields
 * - Sends synchronous ubus notification with 1000ms timeout via ubus_notify()
 * - BLOCKS event loop for up to 1000ms waiting for subscriber acknowledgment
 * - Logs errors if blob operations fail (via CHECK macro)
 *
 * THREAD SAFETY:
 * Must be called from main event loop thread. Not reentrant. Synchronous timeout blocks further processing.
 */
void ubus_event_bcast_connmark_allowlist_resolved(u32 mark, const char *name, const char *value, u32 ttl)
{
  struct ubus_context *ubus = (struct ubus_context *)daemon->ubus;

  if (!ubus || !ubus_object.has_subscribers)
    return;

  CHECK(blob_buf_init(&b, 0));
  CHECK(blobmsg_add_u32(&b, "mark", mark));
  CHECK(blobmsg_add_string(&b, "name", name));
  CHECK(blobmsg_add_string(&b, "value", value));
  CHECK(blobmsg_add_u32(&b, "ttl", ttl));
  
  /* Set timeout to allow UBus subscriber to configure firewall rules before returning. */
  CHECK(ubus_notify(ubus, &ubus_object, "connmark-allowlist.resolved", b.head, /* timeout: */ 1000));
}
#endif

#undef CHECK

#endif /* HAVE_UBUS */
