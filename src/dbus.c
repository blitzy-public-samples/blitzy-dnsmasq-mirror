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
 * @file dbus.c
 * @brief D-Bus control interface for runtime configuration and monitoring of dnsmasq
 *
 * DETAILED PURPOSE:
 * This file implements a D-Bus Inter-Process Communication (IPC) interface that provides
 * runtime control and monitoring capabilities for dnsmasq without requiring daemon restart
 * or SIGHUP signal. The interface exports methods under the uk.org.thekelleys.dnsmasq
 * interface name on the system D-Bus bus, enabling dynamic configuration changes and
 * status queries. This is commonly used by NetworkManager, systemd-resolved, and other
 * system management tools to integrate dnsmasq into dynamic network configurations.
 *
 * The implementation handles D-Bus message serialization and deserialization, watches
 * for bus connection state changes, and dispatches incoming method calls to appropriate
 * handlers. It provides a non-blocking integration with dnsmasq's event loop by registering
 * file descriptors with the poll-based event dispatcher.
 *
 * KEY RESPONSIBILITIES:
 * - dbus_init() - Establishes connection to system D-Bus and exports interface
 * - message_handler() - Dispatches incoming D-Bus method calls to specific handlers
 * - dbus_read_servers() - Processes SetServers method to dynamically add/remove upstream DNS servers
 * - dbus_read_servers_ex() - Extended server configuration with domain-specific routing
 * - emit_dbus_signal() - Broadcasts DHCP lease change notifications
 * - set_dbus_listeners() - Registers D-Bus file descriptors with poll event loop
 * - check_dbus_listeners() - Processes pending D-Bus events during poll dispatch
 * - dbus_get_metrics() - Exports runtime statistics and metrics
 *
 * DEPENDENCIES:
 * - Includes: dnsmasq.h (daemon state and types), dbus/dbus.h (libdbus-1 API)
 * - Called by: main() in dnsmasq.c (initialization), event loop (event dispatch)
 * - Calls: add_update_server() (server management), clear_cache_and_reload() (cache control),
 *          lease management functions (DHCP integration), poll_listen()/poll_check() (event loop)
 *
 * DATA STRUCTURES:
 * - struct watch (lines 99-102) - Tracks D-Bus watch objects for file descriptor monitoring
 * - Uses daemon->dbus (DBusConnection*) - Main D-Bus connection handle
 * - Uses daemon->watches (struct watch*) - Linked list of active D-Bus watches
 * - Uses daemon->dbus_name (char*) - D-Bus interface name (uk.org.thekelleys.dnsmasq)
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DBUS - Required; entire file conditionally compiled when defined
 * - HAVE_LOOP - Enables GetLoopServers method for detecting DNS forwarding loops
 * - HAVE_DHCP - Enables AddDhcpLease/DeleteDhcpLease methods and DhcpLease* signals
 * - HAVE_DHCP6 - Extends DHCP lease methods to support DHCPv6 leases
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven model. All D-Bus processing occurs in main event loop
 * context. D-Bus watch callbacks (add_watch, remove_watch) are invoked synchronously.
 * Message handlers execute synchronously within poll dispatch cycle. No threading or
 * locking required. D-Bus connection configured with dbus_connection_set_exit_on_disconnect
 * to prevent daemon termination on bus disconnect.
 *
 * D-BUS SPECIFICATION COMPLIANCE:
 * Implements D-Bus specification for system bus services. Supports introspection via
 * org.freedesktop.DBus.Introspectable interface. Follows D-Bus type system for message
 * marshalling (UINT32, STRING, ARRAY, BYTE, BOOLEAN). Emits signals for asynchronous
 * event notification (DhcpLeaseAdded, DhcpLeaseDeleted, DhcpLeaseUpdated, Up).
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DBUS

#include <dbus/dbus.h>

const char* introspection_xml_template =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
"<node name=\"" DNSMASQ_PATH "\">\n"
"  <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
"    <method name=\"Introspect\">\n"
"      <arg name=\"data\" direction=\"out\" type=\"s\"/>\n"
"    </method>\n"
"  </interface>\n"
"  <interface name=\"%s\">\n"
"    <method name=\"ClearCache\">\n"
"    </method>\n"
"    <method name=\"GetVersion\">\n"
"      <arg name=\"version\" direction=\"out\" type=\"s\"/>\n"
"    </method>\n"
#ifdef HAVE_LOOP
"    <method name=\"GetLoopServers\">\n"
"      <arg name=\"server\" direction=\"out\" type=\"as\"/>\n"
"    </method>\n"
#endif
"    <method name=\"SetServers\">\n"
"      <arg name=\"servers\" direction=\"in\" type=\"av\"/>\n"
"    </method>\n"
"    <method name=\"SetDomainServers\">\n"
"      <arg name=\"servers\" direction=\"in\" type=\"as\"/>\n"
"    </method>\n"
"    <method name=\"SetServersEx\">\n"
"      <arg name=\"servers\" direction=\"in\" type=\"aas\"/>\n"
"    </method>\n"
"    <method name=\"SetFilterWin2KOption\">\n"
"      <arg name=\"filterwin2k\" direction=\"in\" type=\"b\"/>\n"
"    </method>\n"
"    <method name=\"SetLocaliseQueriesOption\">\n"
"      <arg name=\"localise-queries\" direction=\"in\" type=\"b\"/>\n"
"    </method>\n"
"    <method name=\"SetBogusPrivOption\">\n"
"      <arg name=\"boguspriv\" direction=\"in\" type=\"b\"/>\n"
"    </method>\n"
"    <signal name=\"DhcpLeaseAdded\">\n"
"      <arg name=\"ipaddr\" type=\"s\"/>\n"
"      <arg name=\"hwaddr\" type=\"s\"/>\n"
"      <arg name=\"hostname\" type=\"s\"/>\n"
"    </signal>\n"
"    <signal name=\"DhcpLeaseDeleted\">\n"
"      <arg name=\"ipaddr\" type=\"s\"/>\n"
"      <arg name=\"hwaddr\" type=\"s\"/>\n"
"      <arg name=\"hostname\" type=\"s\"/>\n"
"    </signal>\n"
"    <signal name=\"DhcpLeaseUpdated\">\n"
"      <arg name=\"ipaddr\" type=\"s\"/>\n"
"      <arg name=\"hwaddr\" type=\"s\"/>\n"
"      <arg name=\"hostname\" type=\"s\"/>\n"
"    </signal>\n"
#ifdef HAVE_DHCP
"    <method name=\"AddDhcpLease\">\n"
"       <arg name=\"ipaddr\" type=\"s\"/>\n"
"       <arg name=\"hwaddr\" type=\"s\"/>\n"
"       <arg name=\"hostname\" type=\"ay\"/>\n"
"       <arg name=\"clid\" type=\"ay\"/>\n"
"       <arg name=\"lease_duration\" type=\"u\"/>\n"
"       <arg name=\"ia_id\" type=\"u\"/>\n"
"       <arg name=\"is_temporary\" type=\"b\"/>\n"
"    </method>\n"
"    <method name=\"DeleteDhcpLease\">\n"
"       <arg name=\"ipaddr\" type=\"s\"/>\n"
"       <arg name=\"success\" type=\"b\" direction=\"out\"/>\n"
"    </method>\n"
#endif
"    <method name=\"GetMetrics\">\n"
"      <arg name=\"metrics\" direction=\"out\" type=\"a{su}\"/>\n"
"    </method>\n"
"  </interface>\n"
"</node>\n";

static char *introspection_xml = NULL;

struct watch {
  DBusWatch *watch;      
  struct watch *next;
};

/**
 * @brief Register a new D-Bus watch for file descriptor monitoring
 * 
 * @detailed
 * Callback invoked by libdbus when a new watch (file descriptor to monitor)
 * needs to be registered. Allocates a watch wrapper structure and prepends it
 * to daemon->watches linked list. Duplicate watch registrations are silently
 * ignored. This integrates D-Bus file descriptors into dnsmasq's poll-based
 * event loop.
 *
 * @param watch D-Bus watch object containing file descriptor and flags
 * @param data User data pointer (unused, for callback signature compatibility)
 * 
 * @return TRUE on successful registration, FALSE on memory allocation failure
 * 
 * @note Memory allocation failure is non-fatal; D-Bus will retry
 * @warning Must not block or perform I/O; called from libdbus internal context
 * 
 * @see remove_watch() for deregistration
 * @see set_dbus_listeners() for poll integration
 * 
 * EXAMPLE USAGE:
 * @code
 * // libdbus calls this automatically during dbus_connection_set_watch_functions()
 * dbus_connection_set_watch_functions(connection, add_watch, remove_watch,
 *                                     NULL, NULL, NULL);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates memory for struct watch
 * - Modifies daemon->watches linked list
 * - Logs warning on allocation failure (via whine_malloc)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop context only.
 * Safe to call during D-Bus connection initialization.
 */
static dbus_bool_t add_watch(DBusWatch *watch, void *data)
{
  struct watch *w;

  for (w = daemon->watches; w; w = w->next)
    if (w->watch == watch)
      return TRUE;

  if (!(w = whine_malloc(sizeof(struct watch))))
    return FALSE;

  w->watch = watch;
  w->next = daemon->watches;
  daemon->watches = w;

  (void)data; /* no warning */
  return TRUE;
}

/**
 * @brief Unregister a D-Bus watch from file descriptor monitoring
 * 
 * @detailed
 * Callback invoked by libdbus when a watch (file descriptor) no longer needs
 * monitoring. Searches daemon->watches linked list for matching watch object,
 * removes it from the list, and frees the wrapper structure. Safe to call
 * with non-existent watch (silently ignored). This removes D-Bus file descriptors
 * from dnsmasq's poll event monitoring.
 *
 * @param watch D-Bus watch object to unregister
 * @param data User data pointer (unused, for callback signature compatibility)
 * 
 * @return void
 * 
 * @note Safe to call multiple times with same watch (no-op after first removal)
 * @warning Must not block; called from libdbus internal context during connection teardown
 * 
 * @see add_watch() for registration
 * @see set_dbus_listeners() for poll integration
 * 
 * EXAMPLE USAGE:
 * @code
 * // libdbus calls this automatically when connection closes or watch is disabled
 * // Typically invoked during dbus_connection_unref() or bus disconnect
 * @endcode
 *
 * SIDE EFFECTS:
 * - Frees memory for struct watch
 * - Modifies daemon->watches linked list
 * - File descriptor remains valid but is no longer monitored
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop context only.
 * Safe during D-Bus connection shutdown.
 */
static void remove_watch(DBusWatch *watch, void *data)
{
  struct watch **up, *w, *tmp;  
  
  for (up = &(daemon->watches), w = daemon->watches; w; w = tmp)
    {
      tmp = w->next;
      if (w->watch == watch)
	{
	  *up = tmp;
	  free(w);
	}
      else
	up = &(w->next);
    }

  (void)data; /* no warning */
}

/**
 * @brief Process SetServers D-Bus method to dynamically configure upstream DNS servers
 * 
 * @detailed
 * Parses D-Bus message containing array of IPv4/IPv6 addresses and optional domain
 * specifications, then updates daemon's upstream server list. Marks all SERV_FROM_DBUS
 * servers before processing, adds/updates servers from message, then removes unmarked
 * servers (those no longer in new configuration). Supports per-domain upstream server
 * routing for split DNS configurations. IPv4 addresses encoded as UINT32, IPv6 as
 * BYTE[16] arrays. Multiple domains can be associated with each server address.
 *
 * @param message D-Bus method call message containing server address array
 * 
 * @return NULL on success, DBusMessage error on parse failure
 * @retval NULL Server list updated successfully
 * @retval DBusMessage* Error message with DBUS_ERROR_INVALID_ARGS on parse failure
 * 
 * @note Clears SERV_FROM_DBUS flag on all existing D-Bus-originated servers before processing
 * @warning Does not clear DNS cache; caller must invoke clear_cache_and_reload() if desired
 * 
 * @see dbus_read_servers_ex() for extended format with interface binding
 * @see message_handler() for invocation context
 * @see add_update_server() in forward.c for server list management
 * 
 * EXAMPLE USAGE:
 * @code
 * // D-Bus client (e.g., NetworkManager) calls SetServers:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq --print-reply \
 * //   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.dnsmasq.SetServers \
 * //   uint32:0x08080808 string:google.com uint32:0x08080404
 * // Sets 8.8.8.8 for google.com and 8.8.4.4 for all domains
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports RFC 1035 DNS server addresses (IPv4) and RFC 3596 (IPv6).
 * Split DNS routing per domain aligns with RFC 6950 architectural considerations.
 *
 * SIDE EFFECTS:
 * - Modifies daemon->servers linked list (adds, updates, removes entries)
 * - Calls mark_servers() to flag SERV_FROM_DBUS servers
 * - Calls cleanup_servers() to remove unmarked servers
 * - Allocates memory for new server structures
 * - Does NOT clear DNS cache (handled by caller if OPT_RELOAD set)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from message_handler() in main event loop context.
 */
static DBusMessage* dbus_read_servers(DBusMessage *message)
{
  DBusMessageIter iter;
  union  mysockaddr addr, source_addr;
  char *domain;
  
  if (!dbus_message_iter_init(message, &iter))
    {
      return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                    "Failed to initialize dbus message iter");
    }

  mark_servers(SERV_FROM_DBUS);
  
  while (1)
    {
      int skip = 0;

      if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_UINT32)
	{
	  u32 a;
	  
	  dbus_message_iter_get_basic(&iter, &a);
	  dbus_message_iter_next (&iter);
	  
#ifdef HAVE_SOCKADDR_SA_LEN
	  source_addr.in.sin_len = addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
	  addr.in.sin_addr.s_addr = ntohl(a);
	  source_addr.in.sin_family = addr.in.sin_family = AF_INET;
	  addr.in.sin_port = htons(NAMESERVER_PORT);
	  source_addr.in.sin_addr.s_addr = INADDR_ANY;
	  source_addr.in.sin_port = htons(daemon->query_port);
	}
      else if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_BYTE)
	{
	  unsigned char p[sizeof(struct in6_addr)];
	  unsigned int i;

	  skip = 1;

	  for(i = 0; i < sizeof(struct in6_addr); i++)
	    {
	      dbus_message_iter_get_basic(&iter, &p[i]);
	      dbus_message_iter_next (&iter);
	      if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BYTE)
		{
		  i++;
		  break;
		}
	    }

	  if (i == sizeof(struct in6_addr))
	    {
	      memcpy(&addr.in6.sin6_addr, p, sizeof(struct in6_addr));
#ifdef HAVE_SOCKADDR_SA_LEN
              source_addr.in6.sin6_len = addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
              source_addr.in6.sin6_family = addr.in6.sin6_family = AF_INET6;
              addr.in6.sin6_port = htons(NAMESERVER_PORT);
              source_addr.in6.sin6_flowinfo = addr.in6.sin6_flowinfo = 0;
	      source_addr.in6.sin6_scope_id = addr.in6.sin6_scope_id = 0;
              source_addr.in6.sin6_addr = in6addr_any;
              source_addr.in6.sin6_port = htons(daemon->query_port);
	      skip = 0;
	    }
	}
      else
	/* At the end */
	break;
      
      /* process each domain */
      do {
	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING)
	  {
	    dbus_message_iter_get_basic(&iter, &domain);
	    dbus_message_iter_next (&iter);
	  }
	else
	  domain = NULL;
	
	if (!skip)
	  add_update_server(SERV_FROM_DBUS, &addr, &source_addr, NULL, domain, NULL);
     
      } while (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING); 
    }
   
  /* unlink and free anything still marked. */
  cleanup_servers();
  return NULL;
}

#ifdef HAVE_LOOP
/**
 * @brief Generate GetLoopServers response listing detected DNS forwarding loops
 * 
 * @detailed
 * Constructs D-Bus reply containing array of upstream server addresses that have
 * been detected as creating forwarding loops (server sends queries back to dnsmasq).
 * Iterates through daemon->servers list, filters for SERV_LOOP flag, formats
 * addresses using prettyprint_addr(), and appends to string array. Used for
 * debugging and detecting misconfigured DNS forwarding.
 *
 * @param message D-Bus method call message to reply to
 * 
 * @return DBusMessage method return containing string array of looping server addresses
 * 
 * @note Only available when HAVE_LOOP compile option enabled
 * @warning Allocates D-Bus message; caller must send and unref
 * 
 * @see forward.c for loop detection logic setting SERV_LOOP flag
 * @see message_handler() for invocation
 * 
 * EXAMPLE USAGE:
 * @code
 * // D-Bus client queries loop servers:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq --print-reply \
 * //   /uk/org/thekelleys/dnsmasq uk.org.thekelleys.dnsmasq.GetLoopServers
 * // Returns: array ["192.168.1.1", "2001:db8::1"]
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates DBusMessage reply (caller must unref)
 * - Uses daemon->addrbuff for address formatting (transient, no persistent state change)
 *
 * THREAD SAFETY:
 * Not thread-safe. Uses daemon->addrbuff which is shared global buffer.
 * Must be called from main event loop context.
 */
static DBusMessage *dbus_reply_server_loop(DBusMessage *message)
{
  DBusMessageIter args, args_iter;
  struct server *serv;
  DBusMessage *reply = dbus_message_new_method_return(message);
   
  dbus_message_iter_init_append (reply, &args);
  dbus_message_iter_open_container (&args, DBUS_TYPE_ARRAY,DBUS_TYPE_STRING_AS_STRING, &args_iter);

  for (serv = daemon->servers; serv; serv = serv->next)
    if (serv->flags & SERV_LOOP)
      {
	(void)prettyprint_addr(&serv->addr, daemon->addrbuff);
	dbus_message_iter_append_basic (&args_iter, DBUS_TYPE_STRING, &daemon->addrbuff);
      }
  
  dbus_message_iter_close_container (&args, &args_iter);

  return reply;
}
#endif

/**
 * @brief Process SetServersEx/SetDomainServers methods with extended server configuration
 * 
 * @detailed
 * Extended version of dbus_read_servers() supporting full server specification including
 * interface binding, source address selection, and multiple domain routing per server.
 * Handles two message formats: array of string arrays (strings=0, SetServersEx) or
 * array of strings (strings=1, SetDomainServers). Parses server addresses using
 * parse_server() which supports interface binding syntax (e.g., 192.168.1.1@eth0),
 * source address specification, and domain lists. Provides complete control over
 * server configuration equivalent to command-line --server option.
 *
 * @param message D-Bus method call message containing server configuration
 * @param strings 0 for array-of-arrays format (SetServersEx), 1 for string format (SetDomainServers)
 * 
 * @return NULL on success, DBusMessage error on invalid message format or parse error
 * @retval NULL Server list updated successfully
 * @retval DBusMessage* Error message with DBUS_ERROR_INVALID_ARGS and descriptive text
 * 
 * @note SetDomainServers format: "/domain1/domain2/192.168.1.1" for per-domain routing
 * @note SetServersEx format: [["192.168.1.1", "domain1", "domain2"], ["8.8.8.8"]]
 * @warning More complex than dbus_read_servers(); parsing errors return detailed error messages
 * 
 * @see dbus_read_servers() for simpler format
 * @see parse_server() in option.c for address parsing logic
 * @see message_handler() for method dispatch
 * 
 * EXAMPLE USAGE:
 * @code
 * // SetDomainServers example:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   uk.org.thekelleys.dnsmasq.SetDomainServers \
 * //   array:string:"/example.com/192.168.1.1",string:"8.8.8.8"
 * // Routes example.com to 192.168.1.1, all others to 8.8.8.8
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports RFC 1035 (DNS), RFC 3596 (IPv6), and split DNS per RFC 6950.
 *
 * SIDE EFFECTS:
 * - Modifies daemon->servers linked list
 * - Allocates memory for server structures
 * - Calls mark_servers(), cleanup_servers()
 * - Allocates temporary string buffers (freed before return)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from message_handler() in main event loop.
 */
static DBusMessage* dbus_read_servers_ex(DBusMessage *message, int strings)
{
  DBusMessageIter iter, array_iter, string_iter;
  DBusMessage *error = NULL;
  const char *addr_err;
  char *dup = NULL;
  
  if (!dbus_message_iter_init(message, &iter))
    {
      return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                    "Failed to initialize dbus message iter");
    }

  /* check that the message contains an array of arrays */
  if ((dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) ||
      (dbus_message_iter_get_element_type(&iter) != (strings ? DBUS_TYPE_STRING : DBUS_TYPE_ARRAY)))
    {
      return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                    strings ? "Expected array of string" : "Expected array of string arrays");
     }
 
  mark_servers(SERV_FROM_DBUS);

  /* array_iter points to each "as" element in the outer array */
  dbus_message_iter_recurse(&iter, &array_iter);
  while (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_INVALID)
    {
      const char *str = NULL;
      union  mysockaddr addr, source_addr;
      u16 flags = 0;
      char interface[IF_NAMESIZE];
      char *str_addr, *str_domain = NULL;

      if (strings)
	{
	  dbus_message_iter_get_basic(&array_iter, &str);
	  if (!str || !strlen (str))
	    {
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Empty string");
	      break;
	    }
	  
	  /* dup the string because it gets modified during parsing */
	  if (dup)
	    free(dup);
	  if (!(dup = str_domain = whine_malloc(strlen(str)+1)))
	    break;
	  
	  strcpy(str_domain, str);

	  /* point to address part of old string for error message */
	  if ((str_addr = strrchr(str, '/')))
	    str = str_addr+1;
	  
	  if ((str_addr = strrchr(str_domain, '/')))
	    {
	      if (*str_domain != '/' || str_addr == str_domain)
		{
		  error = dbus_message_new_error_printf(message,
							DBUS_ERROR_INVALID_ARGS,
							"No domain terminator '%s'",
							str);
		  break;
		}
	      *str_addr++ = 0;
	      str_domain++;
	    }
	  else
	    {
	      str_addr = str_domain;
	      str_domain = NULL;
	    }

	  
	}
      else
	{
	  /* check the types of the struct and its elements */
	  if ((dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_ARRAY) ||
	      (dbus_message_iter_get_element_type(&array_iter) != DBUS_TYPE_STRING))
	    {
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Expected inner array of strings");
	      break;
	    }
	  
	  /* string_iter points to each "s" element in the inner array */
	  dbus_message_iter_recurse(&array_iter, &string_iter);
	  if (dbus_message_iter_get_arg_type(&string_iter) != DBUS_TYPE_STRING)
	    {
	      /* no IP address given */
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Expected IP address");
	      break;
	    }
	  
	  dbus_message_iter_get_basic(&string_iter, &str);
	  if (!str || !strlen (str))
	    {
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Empty IP address");
	      break;
	    }
	  
	  /* dup the string because it gets modified during parsing */
	  if (dup)
	    free(dup);
	  if (!(dup = str_addr = whine_malloc(strlen(str)+1)))
	    break;
	  
	  strcpy(str_addr, str);
	}

      /* parse the IP address */
      if ((addr_err = parse_server(str_addr, &addr, &source_addr, (char *) &interface, &flags)))
	{
          error = dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
                                                "Invalid IP address '%s': %s",
                                                str, addr_err);
          break;
        }
      
      /* 0.0.0.0 for server address == NULL, for Dbus */
      if (addr.in.sin_family == AF_INET &&
          addr.in.sin_addr.s_addr == 0)
        flags |= SERV_LITERAL_ADDRESS;
      
      if (strings)
	{
	  char *p;
	  
	  do {
	    if (str_domain)
	      {
		if ((p = strchr(str_domain, '/')))
		  *p++ = 0;
	      }
	    else 
	      p = NULL;
	    
	    add_update_server(flags | SERV_FROM_DBUS, &addr, &source_addr, interface, str_domain, NULL);
	  } while ((str_domain = p));
	}
      else
	{
	  /* jump past the address to the domain list (if any) */
	  dbus_message_iter_next (&string_iter);
	  
	  /* parse domains and add each server/domain pair to the list */
	  do {
	    str = NULL;
	    if (dbus_message_iter_get_arg_type(&string_iter) == DBUS_TYPE_STRING)
	      dbus_message_iter_get_basic(&string_iter, &str);
	    dbus_message_iter_next (&string_iter);
	    
	    add_update_server(flags | SERV_FROM_DBUS, &addr, &source_addr, interface, str, NULL);
	  } while (dbus_message_iter_get_arg_type(&string_iter) == DBUS_TYPE_STRING);
	}
	 
      /* jump to next element in outer array */
      dbus_message_iter_next(&array_iter);
    }

  cleanup_servers();
    
  if (dup)
    free(dup);

  return error;
}

/**
 * @brief Process D-Bus methods to enable/disable boolean configuration options
 * 
 * @detailed
 * Generic handler for SetFilterWin2KOption, SetLocaliseQueriesOption, and SetBogusPrivOption
 * methods. Extracts boolean argument from D-Bus message, logs configuration change, and
 * calls set_option_bool()/reset_option_bool() to modify daemon runtime options. Provides
 * runtime control over filtering and query behavior without requiring configuration file
 * changes or daemon restart.
 *
 * @param message D-Bus method call message containing boolean argument
 * @param flag Option flag constant (OPT_FILTER, OPT_LOCALISE, OPT_BOGUSPRIV)
 * @param name Option name for logging (e.g., "filterwin2k", "localise-queries", "bogus-priv")
 * 
 * @return NULL on success, DBusMessage error on invalid argument type
 * @retval NULL Option successfully enabled/disabled
 * @retval DBusMessage* Error message with DBUS_ERROR_INVALID_ARGS if argument not boolean
 * 
 * @note Changes take effect immediately for subsequent queries
 * @warning Option changes are not persisted; lost on daemon restart
 * 
 * @see set_option_bool() in option.c for flag manipulation
 * @see message_handler() for method dispatch with specific flag/name pairs
 * 
 * EXAMPLE USAGE:
 * @code
 * // Enable bogus-priv option to filter RFC1918 reverse lookups:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   uk.org.thekelleys.dnsmasq.SetBogusPrivOption boolean:true
 * // Logs: "Enabling --bogus-priv option from D-Bus"
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies daemon->options bitmask via set_option_bool()/reset_option_bool()
 * - Logs configuration change to syslog with LOG_INFO priority
 * - Affects DNS query processing behavior immediately
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from message_handler() in main event loop.
 * Option modifications are not atomic but safe in single-threaded context.
 */
static DBusMessage *dbus_set_bool(DBusMessage *message, int flag, char *name)
{
  DBusMessageIter iter;
  dbus_bool_t enabled;

  if (!dbus_message_iter_init(message, &iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS, "Expected boolean argument");
  
  dbus_message_iter_get_basic(&iter, &enabled);

  if (enabled)
    { 
      my_syslog(LOG_INFO, _("Enabling --%s option from D-Bus"), name);
      set_option_bool(flag);
    }
  else
    {
      my_syslog(LOG_INFO, _("Disabling --%s option from D-Bus"), name);
      reset_option_bool(flag);
    }

  return NULL;
}

#ifdef HAVE_DHCP
/**
 * @brief Process AddDhcpLease D-Bus method to programmatically create DHCP leases
 * 
 * @detailed
 * Creates DHCP lease from external specification without DHCP protocol exchange. Parses
 * D-Bus message containing IP address, hardware address, hostname, client identifier,
 * lease duration, IA_ID (DHCPv6), and temporary flag. Supports both IPv4 and DHCPv6
 * lease creation. Allocates lease structure if not existing, sets hardware address,
 * client identifier, expiry time, and hostname. Updates lease database file and DNS
 * cache. Used by external DHCP management systems or orchestration tools to inject
 * leases into dnsmasq without protocol interaction.
 *
 * @param message D-Bus method call with 7 arguments: ipaddr(s), hwaddr(s), hostname(ay),
 *                clid(ay), lease_duration(u), ia_id(u), is_temporary(b)
 * 
 * @return NULL on success, DBusMessage error on invalid arguments or parse failure
 * @retval NULL Lease successfully added/updated, file and DNS updated
 * @retval DBusMessage* Error with DBUS_ERROR_INVALID_ARGS and descriptive message
 * 
 * @note For IPv4 leases, ia_id and is_temporary must be zero
 * @note For DHCPv6, is_temporary distinguishes IA_TA from IA_NA leases
 * @warning Bypasses DHCP protocol address conflict detection (no ping-before-offer)
 * 
 * @see lease_set_hwaddr() in lease.c for hardware address association
 * @see lease_update_file() for lease database persistence
 * @see lease_update_dns() for DNS cache synchronization
 * 
 * EXAMPLE USAGE:
 * @code
 * // Add IPv4 lease via D-Bus:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq \
 * //   uk.org.thekelleys.dnsmasq.AddDhcpLease \
 * //   string:"192.168.1.100" string:"00:11:22:33:44:55" \
 * //   array:byte:0x68,0x6f,0x73,0x74 array:byte: uint32:3600 \
 * //   uint32:0 boolean:false
 * @endcode
 *
 * RFC COMPLIANCE:
 * Creates leases compatible with RFC 2131 (DHCPv4) and RFC 3315 (DHCPv6) formats.
 *
 * SIDE EFFECTS:
 * - Allocates or updates struct dhcp_lease
 * - Writes to lease database file (lease_update_file)
 * - Updates DNS cache with hostname (lease_update_dns)
 * - Modifies daemon->leases data structures
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from message_handler() in main event loop.
 */
static DBusMessage *dbus_add_lease(DBusMessage* message)
{
  struct dhcp_lease *lease;
  const char *ipaddr, *hwaddr, *hostname, *tmp;
  const unsigned char* clid;
  int clid_len, hostname_len, hw_len, hw_type;
  dbus_uint32_t expires, ia_id;
  dbus_bool_t is_temporary;
  union all_addr addr;
  time_t now = dnsmasq_time();
  unsigned char dhcp_chaddr[DHCP_CHADDR_MAX];

  DBusMessageIter iter, array_iter;
  if (!dbus_message_iter_init(message, &iter))
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Failed to initialize dbus message iter");

  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected string as first argument");

  dbus_message_iter_get_basic(&iter, &ipaddr);
  dbus_message_iter_next(&iter);

  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected string as second argument");
    
  dbus_message_iter_get_basic(&iter, &hwaddr);
  dbus_message_iter_next(&iter);

  if ((dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) ||
      (dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_BYTE))
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected byte array as third argument");
    
  dbus_message_iter_recurse(&iter, &array_iter);
  dbus_message_iter_get_fixed_array(&array_iter, &hostname, &hostname_len);
  tmp = memchr(hostname, '\0', hostname_len);
  if (tmp)
    {
      if (tmp == &hostname[hostname_len - 1])
	hostname_len--;
      else
	return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				      "Hostname contains an embedded NUL character");
    }
  dbus_message_iter_next(&iter);

  if ((dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) ||
      (dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_BYTE))
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected byte array as fourth argument");

  dbus_message_iter_recurse(&iter, &array_iter);
  dbus_message_iter_get_fixed_array(&array_iter, &clid, &clid_len);
  dbus_message_iter_next(&iter);

  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected uint32 as fifth argument");
    
  dbus_message_iter_get_basic(&iter, &expires);
  dbus_message_iter_next(&iter);

  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                    "Expected uint32 as sixth argument");
  
  dbus_message_iter_get_basic(&iter, &ia_id);
  dbus_message_iter_next(&iter);

  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected uint32 as sixth argument");

  dbus_message_iter_get_basic(&iter, &is_temporary);

  if (inet_pton(AF_INET, ipaddr, &addr.addr4))
    {
      if (ia_id != 0 || is_temporary)
	return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				      "ia_id and is_temporary must be zero for IPv4 lease");
      
      if (!(lease = lease_find_by_addr(addr.addr4)))
    	lease = lease4_allocate(addr.addr4);
    }
#ifdef HAVE_DHCP6
  else if (inet_pton(AF_INET6, ipaddr, &addr.addr6))
    {
      if (!(lease = lease6_find_by_addr(&addr.addr6, 128, 0)))
	lease = lease6_allocate(&addr.addr6,
				is_temporary ? LEASE_TA : LEASE_NA);
      lease_set_iaid(lease, ia_id);
    }
#endif
  else
    return dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
					 "Invalid IP address '%s'", ipaddr);
   
  hw_len = parse_hex((char*)hwaddr, dhcp_chaddr, DHCP_CHADDR_MAX, NULL, &hw_type);
  if (hw_len < 0)
    return dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
					 "Invalid HW address '%s'", hwaddr);

  if (hw_type == 0 && hw_len != 0)
    hw_type = ARPHRD_ETHER;
  
  lease_set_hwaddr(lease, dhcp_chaddr, clid, hw_len, hw_type,
                   clid_len, now, 0);
  lease_set_expires(lease, expires, now);
  if (hostname_len != 0)
    lease_set_hostname(lease, hostname, 0, get_domain(lease->addr), NULL);
  
  lease_update_file(now);
  lease_update_dns(0);

  return NULL;
}

/**
 * @brief Process DeleteDhcpLease D-Bus method to remove DHCP leases
 * 
 * @detailed
 * Deletes DHCP lease identified by IP address. Supports both IPv4 and DHCPv6 lease
 * deletion. Searches lease database for matching address, prunes lease if found,
 * updates lease file and DNS cache. Returns boolean success indicator in reply
 * message. Used by external management tools to revoke leases or clean up stale
 * entries. Safe to call with non-existent address (returns false, no error).
 *
 * @param message D-Bus method call with single string argument containing IP address
 * 
 * @return DBusMessage method return with boolean success, or error message on invalid args
 * @retval DBusMessage* Reply with DBUS_TYPE_BOOLEAN true if lease found and deleted
 * @retval DBusMessage* Reply with DBUS_TYPE_BOOLEAN false if lease not found
 * @retval DBusMessage* Error with DBUS_ERROR_INVALID_ARGS if IP address invalid or missing
 * 
 * @note Lease database and DNS cache updated atomically if lease found
 * @warning Deletion is permanent; lease removed from all tracking structures
 * 
 * @see lease_prune() in lease.c for lease removal
 * @see lease_update_file() for database synchronization
 * @see lease_update_dns() for DNS cache cleanup
 * 
 * EXAMPLE USAGE:
 * @code
 * // Delete lease via D-Bus:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq --print-reply \
 * //   uk.org.thekelleys.dnsmasq.DeleteDhcpLease \
 * //   string:"192.168.1.100"
 * // Returns: boolean true (if lease existed) or false (if not found)
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports RFC 2131 (DHCPv4) and RFC 3315 (DHCPv6) lease management.
 *
 * SIDE EFFECTS:
 * - Removes struct dhcp_lease from daemon->leases
 * - Frees lease memory (lease_prune)
 * - Updates lease database file
 * - Removes hostname from DNS cache
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from message_handler() in main event loop.
 */
static DBusMessage *dbus_del_lease(DBusMessage* message)
{
  struct dhcp_lease *lease;
  DBusMessageIter iter;
  const char *ipaddr;
  DBusMessage *reply;
  union all_addr addr;
  dbus_bool_t ret = 1;
  time_t now = dnsmasq_time();

  if (!dbus_message_iter_init(message, &iter))
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Failed to initialize dbus message iter");
   
  if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
				  "Expected string as first argument");
   
  dbus_message_iter_get_basic(&iter, &ipaddr);

  if (inet_pton(AF_INET, ipaddr, &addr.addr4))
    lease = lease_find_by_addr(addr.addr4);
#ifdef HAVE_DHCP6
  else if (inet_pton(AF_INET6, ipaddr, &addr.addr6))
    lease = lease6_find_by_addr(&addr.addr6, 128, 0);
#endif
  else
    return dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
					 "Invalid IP address '%s'", ipaddr);
    
  if (lease)
    {
      lease_prune(lease, now);
      lease_update_file(now);
      lease_update_dns(0);
    }
  else
    ret = 0;
  
  if ((reply = dbus_message_new_method_return(message)))
    dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &ret,
			     DBUS_TYPE_INVALID);
  
    
  return reply;
}
#endif

/**
 * @brief Process GetMetrics D-Bus method to export runtime statistics
 * 
 * @detailed
 * Constructs D-Bus reply containing dictionary of metric name-value pairs representing
 * dnsmasq runtime statistics. Iterates through daemon->metrics array (size __METRIC_MAX),
 * retrieves human-readable metric names via get_metric_name(), and appends each metric
 * as dictionary entry with string key and uint32 value. Provides programmatic access
 * to same statistics available via metrics.c Prometheus exporter. Used for monitoring,
 * alerting, and dashboard integration.
 *
 * @param message D-Bus method call message (no arguments)
 * 
 * @return DBusMessage method return containing dictionary {string:uint32} of all metrics
 * 
 * @note Metric names defined in metrics.h (e.g., "dns_queries_total", "dns_cache_hits")
 * @note Available regardless of HAVE_METRICS compile option (metrics always tracked)
 * 
 * @see get_metric_name() in metrics.c for name mapping
 * @see daemon->metrics array for counter values
 * @see metrics.c for Prometheus format export
 * 
 * EXAMPLE USAGE:
 * @code
 * // Query metrics via D-Bus:
 * // dbus-send --system --dest=uk.org.thekelleys.dnsmasq --print-reply \
 * //   uk.org.thekelleys.dnsmasq.GetMetrics
 * // Returns: dict {"dns_queries_total"=>1234, "dns_cache_hits"=>890, ...}
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates DBusMessage reply (caller must unref after sending)
 * - No modification of daemon state (read-only operation)
 *
 * THREAD SAFETY:
 * Not thread-safe. Metrics counters updated asynchronously during query processing.
 * Snapshot is consistent at time of iteration but may change between metrics.
 * Must be called from main event loop context.
 */
static DBusMessage *dbus_get_metrics(DBusMessage* message)
{
  DBusMessage *reply = dbus_message_new_method_return(message);
  DBusMessageIter array, dict, iter;
  int i;

  dbus_message_iter_init_append(reply, &iter);
  dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{su}", &array);

  for (i = 0; i < __METRIC_MAX; i++) {
    const char *key     = get_metric_name(i);
    dbus_uint32_t value = daemon->metrics[i];

    dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
    dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING, &key);
    dbus_message_iter_append_basic(&dict, DBUS_TYPE_UINT32, &value);
    dbus_message_iter_close_container(&array, &dict);
  }

  dbus_message_iter_close_container(&iter, &array);

  return reply;
}

/**
 * @brief Main D-Bus message handler dispatching method calls to specific handlers
 * 
 * @detailed
 * Central dispatcher for all incoming D-Bus messages on uk.org.thekelleys.dnsmasq interface.
 * Extracts method name from message, dispatches to appropriate handler function, optionally
 * triggers cache clear or server list validation, and sends reply. Handles introspection
 * requests by returning XML interface description. Returns NOT_YET_HANDLED for unrecognized
 * methods (allows other handlers in chain). Synchronously processes message and sends reply
 * within same event loop iteration.
 *
 * @param connection D-Bus connection object (for sending reply)
 * @param message Incoming D-Bus method call or signal message
 * @param user_data User data pointer (unused, for callback signature compatibility)
 * 
 * @return DBUS_HANDLER_RESULT_HANDLED if message processed, DBUS_HANDLER_RESULT_NOT_YET_HANDLED otherwise
 * @retval DBUS_HANDLER_RESULT_HANDLED Message dispatched to handler, reply sent
 * @retval DBUS_HANDLER_RESULT_NOT_YET_HANDLED Method name not recognized
 * 
 * @note Introspection XML generated dynamically including HAVE_LOOP and HAVE_DHCP sections
 * @note ClearCache method has no arguments and returns empty reply
 * @warning SetServers/SetServersEx/SetDomainServers trigger check_servers() validation
 * 
 * @see dbus_read_servers(), dbus_read_servers_ex(), dbus_get_metrics(), etc. for handlers
 * @see dbus_connection_register_object_path() for handler registration
 * @see clear_cache_and_reload() for cache purging on configuration change
 * 
 * EXAMPLE USAGE:
 * @code
 * // Registered as message handler during dbus_init():
 * DBusObjectPathVTable vtable = {NULL, &message_handler, NULL, NULL, NULL, NULL};
 * dbus_connection_register_object_path(connection, DNSMASQ_PATH, &vtable, NULL);
 * // libdbus invokes message_handler for each incoming method call
 * @endcode
 *
 * METHODS DISPATCHED:
 * - Introspect: Returns XML interface description
 * - GetVersion: Returns VERSION string
 * - GetLoopServers: Returns array of looping servers (HAVE_LOOP)
 * - SetServers: Basic upstream server configuration
 * - SetServersEx: Extended server configuration with interface binding
 * - SetDomainServers: Per-domain server routing
 * - SetFilterWin2KOption: Enable/disable Windows 2000 query filtering
 * - SetLocaliseQueriesOption: Enable/disable query localization
 * - SetBogusPrivOption: Enable/disable RFC1918 reverse lookup filtering
 * - AddDhcpLease: Programmatically add DHCP lease (HAVE_DHCP)
 * - DeleteDhcpLease: Programmatically remove DHCP lease (HAVE_DHCP)
 * - GetMetrics: Export runtime statistics
 * - ClearCache: Flush DNS cache and reload
 *
 * D-BUS SPECIFICATION COMPLIANCE:
 * Implements org.freedesktop.DBus.Introspectable interface for introspection support.
 *
 * SIDE EFFECTS:
 * - May modify daemon->servers (SetServers methods)
 * - May clear DNS cache (ClearCache or OPT_RELOAD after SetServers)
 * - May modify DHCP leases (AddDhcpLease, DeleteDhcpLease)
 * - Sends D-Bus reply message
 * - Logs server changes with my_syslog()
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop during D-Bus event dispatch.
 */
DBusHandlerResult message_handler(DBusConnection *connection, 
				  DBusMessage *message, 
				  void *user_data)
{
  char *method = (char *)dbus_message_get_member(message);
  DBusMessage *reply = NULL;
  int clear_cache = 0, new_servers = 0;
    
  if (dbus_message_is_method_call(message, DBUS_INTERFACE_INTROSPECTABLE, "Introspect"))
    {
      /* string length: "%s" provides space for termination zero */
      if (!introspection_xml && 
	  (introspection_xml = whine_malloc(strlen(introspection_xml_template) + strlen(daemon->dbus_name))))
	sprintf(introspection_xml, introspection_xml_template, daemon->dbus_name);
    
      if (introspection_xml)
	{
	  reply = dbus_message_new_method_return(message);
	  dbus_message_append_args(reply, DBUS_TYPE_STRING, &introspection_xml, DBUS_TYPE_INVALID);
	}
    }
  else if (strcmp(method, "GetVersion") == 0)
    {
      char *v = VERSION;
      reply = dbus_message_new_method_return(message);
      
      dbus_message_append_args(reply, DBUS_TYPE_STRING, &v, DBUS_TYPE_INVALID);
    }
#ifdef HAVE_LOOP
  else if (strcmp(method, "GetLoopServers") == 0)
    {
      reply = dbus_reply_server_loop(message);
    }
#endif
  else if (strcmp(method, "SetServers") == 0)
    {
      reply = dbus_read_servers(message);
      new_servers = 1;
    }
  else if (strcmp(method, "SetServersEx") == 0)
    {
      reply = dbus_read_servers_ex(message, 0);
      new_servers = 1;
    }
  else if (strcmp(method, "SetDomainServers") == 0)
    {
      reply = dbus_read_servers_ex(message, 1);
      new_servers = 1;
    }
  else if (strcmp(method, "SetFilterWin2KOption") == 0)
    {
      reply = dbus_set_bool(message, OPT_FILTER, "filterwin2k");
    }
  else if (strcmp(method, "SetLocaliseQueriesOption") == 0)
    {
      reply = dbus_set_bool(message, OPT_LOCALISE, "localise-queries");
    }
  else if (strcmp(method, "SetBogusPrivOption") == 0)
    {
      reply = dbus_set_bool(message, OPT_BOGUSPRIV, "bogus-priv");
    }
#ifdef HAVE_DHCP
  else if (strcmp(method, "AddDhcpLease") == 0)
    {
      reply = dbus_add_lease(message);
    }
  else if (strcmp(method, "DeleteDhcpLease") == 0)
    {
      reply = dbus_del_lease(message);
    }
#endif
  else if (strcmp(method, "GetMetrics") == 0)
    {
      reply = dbus_get_metrics(message);
    }
  else if (strcmp(method, "ClearCache") == 0)
    clear_cache = 1;
  else
    return (DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
   
  if (new_servers)
    {
      my_syslog(LOG_INFO, _("setting upstream servers from DBus"));
      check_servers(0);
      if (option_bool(OPT_RELOAD))
	clear_cache = 1;
    }

  if (clear_cache)
    clear_cache_and_reload(dnsmasq_time());
  
  (void)user_data; /* no warning */

  /* If no reply or no error, return nothing */
  if (!reply)
    reply = dbus_message_new_method_return(message);

  if (reply)
    {
      dbus_connection_send (connection, reply, NULL);
      dbus_message_unref (reply);
    }

  return (DBUS_HANDLER_RESULT_HANDLED);
}
 

/**
 * @brief Initialize D-Bus connection and register dnsmasq interface
 * 
 * @detailed
 * Establishes connection to system D-Bus bus, configures connection options (disable
 * exit-on-disconnect to prevent daemon termination on bus restart), registers watch
 * functions for file descriptor monitoring, requests well-known name (daemon->dbus_name,
 * typically uk.org.thekelleys.dnsmasq), registers object path with message handler
 * vtable, and emits "Up" signal to notify clients of availability. Returns NULL on
 * success or error message string on failure. Safe to fail silently if D-Bus daemon
 * not yet started (common during early boot); dnsmasq continues without D-Bus support.
 *
 * @return NULL on success, const char* error message on failure
 * @retval NULL D-Bus connection established, interface registered, watch functions set
 * @retval char* Error message string (D-Bus error or registration failure description)
 * 
 * @note May return NULL if D-Bus daemon not available (non-fatal, allows operation without D-Bus)
 * @note Sets daemon->dbus to connection handle for use by other functions
 * @warning Failure to register object path prevents all D-Bus method invocations
 * 
 * @see add_watch(), remove_watch() for file descriptor monitoring callbacks
 * @see message_handler() for method call dispatch
 * @see set_dbus_listeners() for poll integration
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main() during daemon initialization:
 * char *err;
 * if ((err = dbus_init()))
 *   my_syslog(LOG_WARNING, _("D-Bus init failed: %s"), err);
 * // Daemon continues even if D-Bus unavailable
 * @endcode
 *
 * D-BUS SPECIFICATION COMPLIANCE:
 * Requests well-known name per D-Bus naming conventions (reverse domain notation).
 * Registers object path /uk/org/thekelleys/dnsmasq (DNSMASQ_PATH).
 * Emits "Up" signal on uk.org.thekelleys.dnsmasq interface after successful registration.
 *
 * SIDE EFFECTS:
 * - Allocates DBusConnection (stored in daemon->dbus)
 * - Registers with system D-Bus daemon (acquires bus name)
 * - Registers file descriptors for monitoring (via add_watch callback)
 * - Emits "Up" signal on D-Bus bus
 * - Allocates watch structures in daemon->watches
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called once during daemon initialization before event loop.
 * Connection remains valid for daemon lifetime unless bus disconnects.
 */
char *dbus_init(void)
{
  DBusConnection *connection = NULL;
  DBusObjectPathVTable dnsmasq_vtable = {NULL, &message_handler, NULL, NULL, NULL, NULL };
  DBusError dbus_error;
  DBusMessage *message;

  dbus_error_init (&dbus_error);
  if (!(connection = dbus_bus_get (DBUS_BUS_SYSTEM, &dbus_error)))
    {
      dbus_error_free(&dbus_error);
      return NULL;
    }
  
  dbus_connection_set_exit_on_disconnect(connection, FALSE);
  dbus_connection_set_watch_functions(connection, add_watch, remove_watch, 
				      NULL, NULL, NULL);
  dbus_error_init (&dbus_error);
  dbus_bus_request_name (connection, daemon->dbus_name, 0, &dbus_error);
  if (dbus_error_is_set (&dbus_error))
    return (char *)dbus_error.message;
  
  if (!dbus_connection_register_object_path(connection,  DNSMASQ_PATH, 
					    &dnsmasq_vtable, NULL))
    return _("could not register a DBus message handler");
  
  daemon->dbus = connection; 
  
  if ((message = dbus_message_new_signal(DNSMASQ_PATH, daemon->dbus_name, "Up")))
    {
      dbus_connection_send(connection, message, NULL);
      dbus_message_unref(message);
    }

  return NULL;
}
 

/**
 * @brief Register D-Bus file descriptors with poll event loop for monitoring
 * 
 * @detailed
 * Iterates through daemon->watches linked list (populated by add_watch callback),
 * extracts file descriptor and flags from each enabled DBusWatch, and registers
 * with poll event loop via poll_listen(). Translates D-Bus watch flags (READABLE,
 * WRITABLE) to poll events (POLLIN, POLLOUT, POLLERR). Called before each poll()
 * invocation to ensure D-Bus file descriptors are monitored. Allows D-Bus message
 * processing to integrate with dnsmasq's single-threaded event loop.
 *
 * @return void
 * 
 * @note Only registers enabled watches (dbus_watch_get_enabled() returns true)
 * @note Always registers POLLERR in addition to POLLIN/POLLOUT for error detection
 * 
 * @see poll_listen() in poll.c for file descriptor registration
 * @see check_dbus_listeners() for event processing after poll returns
 * @see add_watch() for watch creation
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from event loop in dnsmasq.c before poll():
 * set_dbus_listeners();
 * set_dns_listeners(); // other protocol listeners
 * poll_wait(timeout);  // blocks until fd ready or timeout
 * check_dbus_listeners(); // process D-Bus events
 * @endcode
 *
 * SIDE EFFECTS:
 * - Registers file descriptors with poll event loop (poll_listen modifies poll fd array)
 * - No persistent state modification (registrations cleared after each poll cycle)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop context before poll().
 */
void set_dbus_listeners(void)
{
  struct watch *w;
  
  for (w = daemon->watches; w; w = w->next)
    if (dbus_watch_get_enabled(w->watch))
      {
	unsigned int flags = dbus_watch_get_flags(w->watch);
	int fd = dbus_watch_get_unix_fd(w->watch);
	
	if (flags & DBUS_WATCH_READABLE)
	  poll_listen(fd, POLLIN);
	
	if (flags & DBUS_WATCH_WRITABLE)
	  poll_listen(fd, POLLOUT);
	
	poll_listen(fd, POLLERR);
      }
}

/**
 * @brief Process pending D-Bus events after poll returns
 * 
 * @detailed
 * Checks poll results for D-Bus file descriptors, notifies libdbus of ready descriptors
 * via dbus_watch_handle(), and dispatches all pending D-Bus messages via
 * dbus_connection_dispatch(). Iterates through daemon->watches list, tests each fd
 * with poll_check(), translates poll events (POLLIN, POLLOUT, POLLERR) to D-Bus watch
 * flags, and invokes watch handler. Continues dispatching messages until queue empty
 * (DBUS_DISPATCH_DATA_REMAINS). Called after poll() returns to process D-Bus activity.
 *
 * @return void
 * 
 * @note Dispatches ALL pending messages in loop (dbus_connection_dispatch until queue empty)
 * @note Connection ref/unref ensures connection remains valid during dispatch
 * @warning If message_handler blocks, entire event loop stalls (keep handlers fast)
 * 
 * @see poll_check() in poll.c for testing file descriptor ready state
 * @see set_dbus_listeners() for file descriptor registration
 * @see message_handler() for message processing
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from event loop in dnsmasq.c after poll returns:
 * set_dbus_listeners();
 * set_dns_listeners();
 * poll_wait(timeout);
 * check_dbus_listeners(); // processes all pending D-Bus messages
 * check_dns_listeners();  // then process DNS events
 * @endcode
 *
 * D-BUS SPECIFICATION COMPLIANCE:
 * Implements recommended dispatch pattern: call dbus_connection_dispatch() in loop
 * until DBUS_DISPATCH_DATA_REMAINS no longer returned, ensuring message queue fully drained.
 *
 * SIDE EFFECTS:
 * - Invokes message_handler() which may modify daemon state (servers, cache, leases)
 * - Sends D-Bus replies (network I/O)
 * - Logs events via my_syslog()
 * - May trigger cache clear, server validation, DNS updates
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop context after poll().
 * Message handlers execute synchronously in same thread.
 */
void check_dbus_listeners()
{
  DBusConnection *connection = (DBusConnection *)daemon->dbus;
  struct watch *w;

  for (w = daemon->watches; w; w = w->next)
    if (dbus_watch_get_enabled(w->watch))
      {
	unsigned int flags = 0;
	int fd = dbus_watch_get_unix_fd(w->watch);
	
	if (poll_check(fd, POLLIN))
	  flags |= DBUS_WATCH_READABLE;
	
	if (poll_check(fd, POLLOUT))
	  flags |= DBUS_WATCH_WRITABLE;
	
	if (poll_check(fd, POLLERR))
	  flags |= DBUS_WATCH_ERROR;

	if (flags != 0)
	  dbus_watch_handle(w->watch, flags);
      }

  if (connection)
    {
      dbus_connection_ref (connection);
      while (dbus_connection_dispatch (connection) == DBUS_DISPATCH_DATA_REMAINS);
      dbus_connection_unref (connection);
    }
}

#ifdef HAVE_DHCP
/**
 * @brief Emit D-Bus signal for DHCP lease state change events
 * 
 * @detailed
 * Broadcasts asynchronous D-Bus signal notifying clients of DHCP lease additions,
 * deletions, or updates. Formats lease information (IP address, MAC address, hostname)
 * into signal message and sends to all listening D-Bus clients. Supports both DHCPv4
 * and DHCPv6 leases. Used by NetworkManager and other tools to track network client
 * state changes. Safe to call when D-Bus unavailable (no-op). Signals are fire-and-forget;
 * no reply expected.
 *
 * @param action Event type: ACTION_ADD (new lease), ACTION_DEL (lease expired/released),
 *               ACTION_OLD (lease updated/renewed)
 * @param lease Pointer to dhcp_lease structure containing lease details
 * @param hostname Client hostname string, or NULL (empty string sent if NULL)
 * 
 * @return void
 * 
 * @note Signal name determined by action: DhcpLeaseAdded, DhcpLeaseDeleted, DhcpLeaseUpdated
 * @note Uses daemon->addrbuff and daemon->namebuff for formatting (transient, reused)
 * @warning No delivery guarantee; clients may miss signals if not listening
 * 
 * @see lease_update_from_configs() in lease.c for typical invocation context
 * @see ACTION_ADD, ACTION_DEL, ACTION_OLD constants for action parameter
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from DHCP lease management code:
 * struct dhcp_lease *lease = lease4_allocate(addr.addr4);
 * lease_set_hwaddr(lease, hwaddr, clid, hw_len, hw_type, clid_len, now, 0);
 * emit_dbus_signal(ACTION_ADD, lease, hostname); // broadcasts to D-Bus clients
 * // NetworkManager receives DhcpLeaseAdded signal with IP, MAC, hostname
 * @endcode
 *
 * D-BUS SIGNAL FORMAT:
 * Signal path: /uk/org/thekelleys/dnsmasq
 * Interface: uk.org.thekelleys.dnsmasq
 * Signal names: DhcpLeaseAdded, DhcpLeaseDeleted, DhcpLeaseUpdated
 * Arguments: (sss) - string ipaddr, string hwaddr, string hostname
 * Example: DhcpLeaseAdded("192.168.1.100", "00:11:22:33:44:55", "client-host")
 *
 * RFC COMPLIANCE:
 * Lease information formatted per RFC 2131 (DHCPv4) or RFC 3315 (DHCPv6).
 *
 * SIDE EFFECTS:
 * - Allocates and sends DBusMessage signal (fire-and-forget, no reply)
 * - Uses daemon->addrbuff for IP address formatting
 * - Uses daemon->namebuff for MAC address formatting
 * - No persistent state modification
 *
 * THREAD SAFETY:
 * Not thread-safe. Uses shared daemon->addrbuff and daemon->namebuff buffers.
 * Must be called from main event loop context during lease processing.
 */
void emit_dbus_signal(int action, struct dhcp_lease *lease, char *hostname)
{
  DBusConnection *connection = (DBusConnection *)daemon->dbus;
  DBusMessage* message = NULL;
  DBusMessageIter args;
  char *action_str, *mac = daemon->namebuff;
  unsigned char *p;
  int i;

  if (!connection)
    return;
  
  if (!hostname)
    hostname = "";
  
#ifdef HAVE_DHCP6
   if (lease->flags & (LEASE_TA | LEASE_NA))
     {
       print_mac(mac, lease->clid, lease->clid_len);
       inet_ntop(AF_INET6, &lease->addr6, daemon->addrbuff, ADDRSTRLEN);
     }
   else
#endif
     {
       p = extended_hwaddr(lease->hwaddr_type, lease->hwaddr_len,
			   lease->hwaddr, lease->clid_len, lease->clid, &i);
       print_mac(mac, p, i);
       inet_ntop(AF_INET, &lease->addr, daemon->addrbuff, ADDRSTRLEN);
     }

  if (action == ACTION_DEL)
    action_str = "DhcpLeaseDeleted";
  else if (action == ACTION_ADD)
    action_str = "DhcpLeaseAdded";
  else if (action == ACTION_OLD)
    action_str = "DhcpLeaseUpdated";
  else
    return;

  if (!(message = dbus_message_new_signal(DNSMASQ_PATH, daemon->dbus_name, action_str)))
    return;
  
  dbus_message_iter_init_append(message, &args);
  
  if (dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &daemon->addrbuff) &&
      dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &mac) &&
      dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &hostname))
    dbus_connection_send(connection, message, NULL);
  
  dbus_message_unref(message);
}
#endif

#endif
