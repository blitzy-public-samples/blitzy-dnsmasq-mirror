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
 * @file helper.c
 * @brief Privileged helper process for lease-change scripts and Lua integration
 * 
 * DETAILED PURPOSE:
 * This file implements a privilege separation architecture where the main dnsmasq daemon
 * drops root privileges for security, but forks a separate helper process that retains
 * root privileges to execute external lease-change scripts. The helper process runs 
 * continuously, receiving lease events via a Unix domain socket from the main process,
 * and invoking configured scripts (--dhcp-script) or Lua functions (--dhcp-luascript)
 * with appropriate environment variables containing lease information.
 * 
 * The privilege separation model ensures that even if the main daemon is compromised,
 * an attacker cannot easily gain root access, as the helper process validates all data
 * received from the main process and only executes the pre-configured script path that
 * was set before forking. The helper supports DHCPv4, DHCPv6, TFTP, and ARP events,
 * passing detailed information via DNSMASQ_* environment variables to scripts or Lua
 * table fields for programmatic access.
 * 
 * Communication is two-way: the main process sends event data to the helper, and the
 * helper sends back script output, error conditions, and completion status for logging
 * by the main daemon. The helper can operate in both script mode (executes external
 * programs) and Lua mode (calls Lua functions), with Lua providing more efficient
 * in-process event handling.
 * 
 * KEY RESPONSIBILITIES:
 * - create_helper() - Fork privileged helper process and establish communication pipe
 * - Helper main loop (lines 182-688) - Receive events and dispatch to scripts or Lua
 * - queue_script() - Serialize DHCP lease events for transmission to helper
 * - queue_tftp() - Serialize TFTP transfer events for transmission to helper
 * - queue_arp() - Serialize ARP detection events for transmission to helper
 * - helper_write() - Write queued events to helper process via socket
 * - my_setenv() - Set environment variables for script execution
 * - grab_extradata() - Extract DHCP option data into environment variables
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (all daemon structures and prototypes)
 * Called by: Main daemon during initialization (create_helper) and event processing
 *           (queue_script, queue_tftp, queue_arp, helper_write)
 * Calls: System functions (fork, pipe, setuid, setgid, execl, setenv)
 *        Lua functions (if HAVE_LUASCRIPT) - lua_getglobal, lua_call, lua_pushstring
 *        Network functions (inet_ntop)
 *        IPC functions (read_write, send_event)
 * 
 * DATA STRUCTURES:
 * - struct script_data (lines 52-74) - Wire format for event data sent to helper
 * - Static buffer: buf, bytes_in_buf, buf_size (line 76) - Queued event buffer
 * - lua_State *lua (line 46, HAVE_LUASCRIPT) - Lua interpreter state
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_SCRIPT - Required for entire module, enables helper process functionality
 * - HAVE_LUASCRIPT - Adds Lua script integration (lines 36-49, 136-175, 319-496, 732-752)
 * - HAVE_TFTP - Enables TFTP transfer event notifications (lines 64-66, 313-318, 868-895)
 * - HAVE_DHCP6 - Enables DHCPv6 lease events and relay snooping (lines 68-71, 272-285, etc.)
 * - HAVE_BROKEN_RTC - Uses lease length instead of expiry time for embedded systems (lines 59-63)
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model with fork for helper process. The helper process runs
 * independently in a separate address space, communicating with main process via Unix socket.
 * Scripts are executed synchronously (helper waits for completion) via additional fork,
 * with stdout/stderr captured and returned to main process for logging. No threading used.
 * Helper process ignores SIGTERM, SIGINT, SIGALRM to prevent premature termination during
 * script execution.
 * 
 * SECURITY:
 * Helper process maintains root privileges while main daemon drops to --user. Helper is
 * paranoid about data received from main process, validating buffer sizes and never allowing
 * script path to be altered after fork. Environment variable injection is controlled via
 * validated data structures. This architecture protects against compromised main process
 * attempting to gain root access via helper.
 * 
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/DHCP_V4.md for DHCP lease lifecycle
 * @see docs/ARCHITECTURE.md for privilege separation architecture
 */

#include "dnsmasq.h"

#ifdef HAVE_SCRIPT

/* This file has code to fork a helper process which receives data via a pipe 
   shared with the main process and which is responsible for calling a script when
   DHCP leases change.

   The helper process is forked before the main process drops root, so it retains root 
   privs to pass on to the script. For this reason it tries to be paranoid about 
   data received from the main process, in case that has been compromised. We don't
   want the helper to give an attacker root. In particular, the script to be run is
   not settable via the pipe, once the fork has taken place it is not alterable by the 
   main process.
*/

static void my_setenv(const char *name, const char *value, int *error);
static unsigned char *grab_extradata(unsigned char *buf, unsigned char *end,  char *env, int *err);

#ifdef HAVE_LUASCRIPT
#define LUA_COMPAT_ALL
#include <lua.h>  
#include <lualib.h>  
#include <lauxlib.h>  

#ifndef lua_open
#define lua_open()     luaL_newstate()
#endif

lua_State *lua;

static unsigned char *grab_extradata_lua(unsigned char *buf, unsigned char *end, char *field);
#endif

/**
 * @struct script_data
 * @brief Wire format for event data transmitted to helper process
 * 
 * @detailed
 * Defines the binary protocol structure sent from main daemon to helper process over
 * the Unix domain socket. Contains all information needed by helper to invoke scripts
 * with appropriate environment variables or Lua function arguments. Structure is followed
 * by variable-length data: client ID, hostname, and extra DHCP options (concatenated
 * null-terminated strings). Supports DHCPv4, DHCPv6, TFTP, ARP, and relay snoop events.
 * 
 * LIFECYCLE:
 * Allocated via buff_alloc() into static buffer, populated by queue_*() functions,
 * transmitted by helper_write(), and parsed by helper process main loop (lines 182-688).
 * 
 * MEMORY LAYOUT:
 * Fixed-size structure (sizeof varies by compile-time options) followed by variable data.
 * Total size: sizeof(struct script_data) + clid_len + hostname_len + ed_len.
 * 
 * USAGE PATTERNS:
 * 1. Main process: buff_alloc() -> populate fields -> queue in buffer -> helper_write()
 * 2. Helper process: read() full structure -> read() variable data -> parse and execute
 */
struct script_data
{
  int flags;
  int action, hwaddr_len, hwaddr_type;
  int clid_len, hostname_len, ed_len;
  struct in_addr addr, giaddr;
  unsigned int remaining_time;
#ifdef HAVE_BROKEN_RTC
  unsigned int length;
#else
  time_t expires;
#endif
#ifdef HAVE_TFTP
  off_t file_len;
#endif
  struct in6_addr addr6;
#ifdef HAVE_DHCP6
  int vendorclass_count;
  unsigned int iaid;
#endif
  unsigned char hwaddr[DHCP_CHADDR_MAX];
  char interface[IF_NAMESIZE];
};

/**
 * @var buf
 * @brief Global buffer for queuing events to helper process
 * 
 * Static buffer holding struct script_data and variable-length data for transmission
 * to helper. Grown as needed by buff_alloc(), reused across multiple events to minimize
 * allocations. NULL if never allocated or allocation failed.
 */
static struct script_data *buf = NULL;

/**
 * @var bytes_in_buf
 * @brief Number of bytes currently queued in buf awaiting transmission
 * 
 * Tracks amount of data in buf that needs to be written to helper process via
 * helper_write(). Zero means buffer is empty. Decremented on partial writes,
 * cleared on errors.
 */
static size_t bytes_in_buf = 0;

/**
 * @var buf_size
 * @brief Allocated size of buf in bytes
 * 
 * Total allocated capacity of buf. Only grows, never shrinks. Used by buff_alloc()
 * to determine if reallocation needed. Zero if buf never allocated.
 */
static size_t buf_size = 0;

/**
 * @brief Fork privileged helper process for executing lease-change scripts
 * 
 * @detailed
 * Creates a helper process that retains root privileges to execute external scripts
 * (--dhcp-script) or Lua functions (--dhcp-luascript) when DHCP lease events occur.
 * The function creates a pipe for communication, forks a child process, and returns
 * the write end of the pipe to the parent (main daemon) while the child enters an
 * event loop waiting for lease data. The child process optionally drops to specified
 * uid/gid if provided and not in debug mode. If Lua scripting is enabled, the child
 * initializes the Lua interpreter and loads the configured script file before entering
 * the main loop.
 * 
 * @param event_fd File descriptor for sending events back to main daemon
 * @param err_fd File descriptor for sending error events during initialization
 * @param uid User ID to drop privileges to (0 means stay as root)
 * @param gid Group ID to drop privileges to
 * @param max_fd Maximum file descriptor number for closing unneeded descriptors
 * 
 * @return In parent: write end of pipe for sending events to helper
 * @return In child: does not return, enters helper main loop and exits with _exit(0)
 * 
 * @note Called after configuration parsing but before main daemon drops privileges
 * @note Child process ignores SIGTERM, SIGINT, SIGALRM to allow clean script execution
 * @note If fork fails, sends EVENT_PIPE_ERR to err_fd and calls _exit(0)
 * 
 * @warning Child process retains root privileges if uid is 0, security-sensitive
 * @warning Lua initialization failures kill daemon if not in debug/no-fork mode
 * 
 * @see queue_script() for formatting lease event data
 * @see helper_write() for sending queued events to helper
 * @see send_event() in dnsmasq.c for event signaling mechanism
 * 
 * EXAMPLE USAGE:
 * @code
 * int helper_fd = create_helper(daemon->event_fd, daemon->err_fd, 
 *                               daemon->scriptuser_uid, daemon->scriptuser_gid, max_fd);
 * daemon->helperfd = helper_fd;
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Not directly RFC-related, but supports RFC 2131 (DHCPv4) and RFC 3315 (DHCPv6)
 * lease notification requirements.
 * 
 * SIDE EFFECTS:
 * - Forks a child process that runs until daemon shutdown
 * - Creates a pipe for IPC between parent and child
 * - Child closes all file descriptors except pipe, event_fd, and err_fd initially
 * - Child may drop privileges via setuid/setgid
 * - Initializes Lua interpreter in child if HAVE_LUASCRIPT enabled
 * - Sends error events to event_fd or err_fd on failures
 * 
 * THREAD SAFETY:
 * Not thread-safe, calls fork() which has undefined behavior in multi-threaded programs.
 * Safe in dnsmasq's single-threaded event-driven architecture. Child process is completely
 * separate after fork.
 */
int create_helper(int event_fd, int err_fd, uid_t uid, gid_t gid, long max_fd)
{
  pid_t pid;
  int i, pipefd[2];
  struct sigaction sigact;
  unsigned char *alloc_buff = NULL;
  
  /* create the pipe through which the main program sends us commands,
     then fork our process. */
  if (pipe(pipefd) == -1 || !fix_fd(pipefd[1]) || (pid = fork()) == -1)
    {
      send_event(err_fd, EVENT_PIPE_ERR, errno, NULL);
      _exit(0);
    }

  if (pid != 0)
    {
      close(pipefd[0]); /* close reader side */
      return pipefd[1];
    }

  /* ignore SIGTERM and SIGINT, so that we can clean up when the main process gets hit
     and SIGALRM so that we can use sleep() */
  sigact.sa_handler = SIG_IGN;
  sigact.sa_flags = 0;
  sigemptyset(&sigact.sa_mask);
  sigaction(SIGTERM, &sigact, NULL);
  sigaction(SIGALRM, &sigact, NULL);
  sigaction(SIGINT, &sigact, NULL);

  if (!option_bool(OPT_DEBUG) && uid != 0)
    {
      gid_t dummy;
      if (setgroups(0, &dummy) == -1 || 
	  setgid(gid) == -1 || 
	  setuid(uid) == -1)
	{
	  if (option_bool(OPT_NO_FORK))
	    /* send error to daemon process if no-fork */
	    send_event(event_fd, EVENT_USER_ERR, errno, daemon->scriptuser);
	  else
	    {
	      /* kill daemon */
	      send_event(event_fd, EVENT_DIE, 0, NULL);
	      /* return error */
	      send_event(err_fd, EVENT_USER_ERR, errno, daemon->scriptuser);
	    }
	  _exit(0);
	}
    }

  /* close all the sockets etc, we don't need them here. 
     Don't close err_fd, in case the lua-init fails.
     Note that we have to do this before lua init
     so we don't close any lua fds. */
  close_fds(max_fd, pipefd[0], event_fd, err_fd);
  
#ifdef HAVE_LUASCRIPT
  if (daemon->luascript)
    {
      const char *lua_err = NULL;
      lua = lua_open();
      luaL_openlibs(lua);
      
      /* get Lua to load our script file */
      if (luaL_dofile(lua, daemon->luascript) != 0)
	lua_err = lua_tostring(lua, -1);
      else
	{
	  lua_getglobal(lua, "lease");
	  if (lua_type(lua, -1) != LUA_TFUNCTION) 
	    lua_err = _("lease() function missing in Lua script");
	}
      
      if (lua_err)
	{
	  if (option_bool(OPT_NO_FORK) || option_bool(OPT_DEBUG))
	    /* send error to daemon process if no-fork */
	    send_event(event_fd, EVENT_LUA_ERR, 0, (char *)lua_err);
	  else
	    {
	      /* kill daemon */
	      send_event(event_fd, EVENT_DIE, 0, NULL);
	      /* return error */
	      send_event(err_fd, EVENT_LUA_ERR, 0, (char *)lua_err);
	    }
	  _exit(0);
	}
      
      lua_pop(lua, 1);  /* remove nil from stack */
      lua_getglobal(lua, "init");
      if (lua_type(lua, -1) == LUA_TFUNCTION)
	lua_call(lua, 0, 0);
      else
	lua_pop(lua, 1);  /* remove nil from stack */	
    }
#endif

  /* All init done, close our copy of the error pipe, so that main process can return */
  if (err_fd != -1)
    close(err_fd);
    
  /* loop here */
  while(1)
    {
      struct script_data data;
      char *p, *action_str, *hostname = NULL, *domain = NULL;
      unsigned char *buf = (unsigned char *)daemon->namebuff;
      unsigned char *end, *extradata;
      int is6, err = 0;
      int pipeout[2];

      /* Free rarely-allocated memory from previous iteration. */
      if (alloc_buff)
	{
	  free(alloc_buff);
	  alloc_buff = NULL;
	}
      
      /* we read zero bytes when pipe closed: this is our signal to exit */ 
      if (!read_write(pipefd[0], (unsigned char *)&data, sizeof(data), 1))
	{
#ifdef HAVE_LUASCRIPT
	  if (daemon->luascript)
	    {
	      lua_getglobal(lua, "shutdown");
	      if (lua_type(lua, -1) == LUA_TFUNCTION)
		lua_call(lua, 0, 0);
	    }
#endif
	  _exit(0);
	}
 
      is6 = !!(data.flags & (LEASE_TA | LEASE_NA));
      
      if (data.action == ACTION_DEL)
	action_str = "del";
      else if (data.action == ACTION_ADD)
	action_str = "add";
      else if (data.action == ACTION_OLD || data.action == ACTION_OLD_HOSTNAME)
	action_str = "old";
      else if (data.action == ACTION_TFTP)
	{
	  action_str = "tftp";
	  is6 = (data.flags != AF_INET);
	}
      else if (data.action == ACTION_ARP)
	{
	  action_str = "arp-add";
	  is6 = (data.flags != AF_INET);
	}
       else if (data.action == ACTION_ARP_DEL)
	{
	  action_str = "arp-del";
	  is6 = (data.flags != AF_INET);
	  data.action = ACTION_ARP;
	}
       else if (data.action == ACTION_RELAY_SNOOP)
	 {
	   is6 = 1;
	   action_str = "relay-snoop";
	 }
       else
	 continue;
      	
      /* stringify MAC into dhcp_buff */
      p = daemon->dhcp_buff;
      if (data.hwaddr_type != ARPHRD_ETHER || data.hwaddr_len == 0) 
	p += sprintf(p, "%.2x-", data.hwaddr_type);
      for (i = 0; (i < data.hwaddr_len) && (i < DHCP_CHADDR_MAX); i++)
	{
	  p += sprintf(p, "%.2x", data.hwaddr[i]);
	  if (i != data.hwaddr_len - 1)
	    p += sprintf(p, ":");
	}
      
      /* supplied data may just exceed normal buffer (unlikely) */
      if ((data.hostname_len + data.ed_len + data.clid_len) > MAXDNAME && 
	  !(alloc_buff = buf = malloc(data.hostname_len + data.ed_len + data.clid_len)))
	continue;
      
      if (!read_write(pipefd[0], buf, 
		      data.hostname_len + data.ed_len + data.clid_len, 1))
	continue;

      /* CLID into packet */
      for (p = daemon->packet, i = 0; i < data.clid_len; i++)
	{
	  p += sprintf(p, "%.2x", buf[i]);
	  if (i != data.clid_len - 1) 
	      p += sprintf(p, ":");
	}

#ifdef HAVE_DHCP6
      if (is6)
	{
	  /* or IAID and server DUID for IPv6 */
	  sprintf(daemon->dhcp_buff3, "%s%u", data.flags & LEASE_TA ? "T" : "", data.iaid);	
	  for (p = daemon->dhcp_packet.iov_base, i = 0; i < daemon->duid_len; i++)
	    {
	      p += sprintf(p, "%.2x", daemon->duid[i]);
	      if (i != daemon->duid_len - 1) 
		p += sprintf(p, ":");
	    }

	}
#endif

      buf += data.clid_len;

      if (data.hostname_len != 0)
	{
	  char *dot;
	  hostname = (char *)buf;
	  hostname[data.hostname_len - 1] = 0;
	  if (data.action != ACTION_TFTP && data.action != ACTION_RELAY_SNOOP)
	    {
	      if (!legal_hostname(hostname))
		hostname = NULL;
	      else if ((dot = strchr(hostname, '.')))
		{
		  domain = dot+1;
		  *dot = 0;
		} 
	    }
	}
    
      extradata = buf + data.hostname_len;
    
      if (!is6)
	inet_ntop(AF_INET, &data.addr, daemon->addrbuff, ADDRSTRLEN);
      else
	inet_ntop(AF_INET6, &data.addr6, daemon->addrbuff, ADDRSTRLEN);

#ifdef HAVE_TFTP
      /* file length */
      if (data.action == ACTION_TFTP)
	sprintf(is6 ? daemon->packet : daemon->dhcp_buff, "%lu", (unsigned long)data.file_len);
#endif

#ifdef HAVE_LUASCRIPT
      if (daemon->luascript)
	{
	  if (data.action == ACTION_TFTP)
	    {
	      lua_getglobal(lua, "tftp"); 
	      if (lua_type(lua, -1) != LUA_TFUNCTION)
		lua_pop(lua, 1); /* tftp function optional */
	      else
		{
		  lua_pushstring(lua, action_str); /* arg1 - action */
		  lua_newtable(lua);               /* arg2 - data table */
		  lua_pushstring(lua, daemon->addrbuff);
		  lua_setfield(lua, -2, "destination_address");
		  lua_pushstring(lua, hostname);
		  lua_setfield(lua, -2, "file_name"); 
		  lua_pushstring(lua, is6 ? daemon->packet : daemon->dhcp_buff);
		  lua_setfield(lua, -2, "file_size");
		  lua_call(lua, 2, 0);	/* pass 2 values, expect 0 */
		}
	    }
	  else if (data.action == ACTION_RELAY_SNOOP)
	    {
	      lua_getglobal(lua, "snoop"); 
	      if (lua_type(lua, -1) != LUA_TFUNCTION)
		lua_pop(lua, 1); /* tftp function optional */
	      else
		{
		  lua_pushstring(lua, action_str); /* arg1 - action */
		  lua_newtable(lua);               /* arg2 - data table */
		  lua_pushstring(lua, daemon->addrbuff);
		  lua_setfield(lua, -2, "client_address");
		  lua_pushstring(lua, hostname);
		  lua_setfield(lua, -2, "prefix"); 
		  lua_pushstring(lua, data.interface);
		  lua_setfield(lua, -2, "client_interface");
		  lua_call(lua, 2, 0);	/* pass 2 values, expect 0 */
		}
	    }
	  else if (data.action == ACTION_ARP)
	    {
	      lua_getglobal(lua, "arp"); 
	      if (lua_type(lua, -1) != LUA_TFUNCTION)
		lua_pop(lua, 1); /* arp function optional */
	      else
		{
		  lua_pushstring(lua, action_str); /* arg1 - action */
		  lua_newtable(lua);               /* arg2 - data table */
		  lua_pushstring(lua, daemon->addrbuff);
		  lua_setfield(lua, -2, "client_address");
		  lua_pushstring(lua, daemon->dhcp_buff);
		  lua_setfield(lua, -2, "mac_address");
		  lua_call(lua, 2, 0);	/* pass 2 values, expect 0 */
		}
	    }
	  else
	    {
	      lua_getglobal(lua, "lease");     /* function to call */
	      lua_pushstring(lua, action_str); /* arg1 - action */
	      lua_newtable(lua);               /* arg2 - data table */
	      
	      if (is6)
		{
		  lua_pushstring(lua, daemon->packet);
		  lua_setfield(lua, -2, "client_duid");
		  lua_pushstring(lua, daemon->dhcp_packet.iov_base);
		  lua_setfield(lua, -2, "server_duid");
		  lua_pushstring(lua, daemon->dhcp_buff3);
		  lua_setfield(lua, -2, "iaid");
		}
	      
	      if (!is6 && data.clid_len != 0)
		{
		  lua_pushstring(lua, daemon->packet);
		  lua_setfield(lua, -2, "client_id");
		}
	      
	      if (strlen(data.interface) != 0)
		{
		  lua_pushstring(lua, data.interface);
		  lua_setfield(lua, -2, "interface");
		}
	      
#ifdef HAVE_BROKEN_RTC	
	      lua_pushnumber(lua, data.length);
	      lua_setfield(lua, -2, "lease_length");
#else
	      lua_pushnumber(lua, data.expires);
	      lua_setfield(lua, -2, "lease_expires");
#endif
	      
	      if (hostname)
		{
		  lua_pushstring(lua, hostname);
		  lua_setfield(lua, -2, "hostname");
		}
	      
	      if (domain)
		{
		  lua_pushstring(lua, domain);
		  lua_setfield(lua, -2, "domain");
		}
	      
	      end = extradata + data.ed_len;
	      buf = extradata;

	      lua_pushnumber(lua, data.ed_len == 0 ? 1 : 0);
	      lua_setfield(lua, -2, "data_missing");
	      
	      if (!is6)
		buf = grab_extradata_lua(buf, end, "vendor_class");
#ifdef HAVE_DHCP6
	      else  if (data.vendorclass_count != 0)
		{
		  sprintf(daemon->dhcp_buff2, "vendor_class_id");
		  buf = grab_extradata_lua(buf, end, daemon->dhcp_buff2);
		  for (i = 0; i < data.vendorclass_count - 1; i++)
		    {
		      sprintf(daemon->dhcp_buff2, "vendor_class%i", i);
		      buf = grab_extradata_lua(buf, end, daemon->dhcp_buff2);
		    }
		}
#endif
	      
	      buf = grab_extradata_lua(buf, end, "supplied_hostname");
	      
	      if (!is6)
		{
		  buf = grab_extradata_lua(buf, end, "cpewan_oui");
		  buf = grab_extradata_lua(buf, end, "cpewan_serial");   
		  buf = grab_extradata_lua(buf, end, "cpewan_class");
		  buf = grab_extradata_lua(buf, end, "circuit_id");
		  buf = grab_extradata_lua(buf, end, "subscriber_id");
		  buf = grab_extradata_lua(buf, end, "remote_id");
		}
	      
	      buf = grab_extradata_lua(buf, end, "tags");
	      
	      if (is6)
		buf = grab_extradata_lua(buf, end, "relay_address");
	      else if (data.giaddr.s_addr != 0)
		{
		  inet_ntop(AF_INET, &data.giaddr, daemon->dhcp_buff2, ADDRSTRLEN);
		  lua_pushstring(lua, daemon->dhcp_buff2);
		  lua_setfield(lua, -2, "relay_address");
		}
	      
	      for (i = 0; buf; i++)
		{
		  sprintf(daemon->dhcp_buff2, "user_class%i", i);
		  buf = grab_extradata_lua(buf, end, daemon->dhcp_buff2);
		}
	      
	      if (data.action != ACTION_DEL && data.remaining_time != 0)
		{
		  lua_pushnumber(lua, data.remaining_time);
		  lua_setfield(lua, -2, "time_remaining");
		}
	      
	      if (data.action == ACTION_OLD_HOSTNAME && hostname)
		{
		  lua_pushstring(lua, hostname);
		  lua_setfield(lua, -2, "old_hostname");
		}
	      
	      if (!is6 || data.hwaddr_len != 0)
		{
		  lua_pushstring(lua, daemon->dhcp_buff);
		  lua_setfield(lua, -2, "mac_address");
		}
	      
	      lua_pushstring(lua, daemon->addrbuff);
	      lua_setfield(lua, -2, "ip_address");
	    
	      lua_call(lua, 2, 0);	/* pass 2 values, expect 0 */
	    }
	}
#endif

      /* no script, just lua */
      if (!daemon->lease_change_command)
	continue;

      /* Pipe to capture stdout and stderr from script */
      if (!option_bool(OPT_DEBUG) && pipe(pipeout) == -1)
	continue;
      
      /* possible fork errors are all temporary resource problems */
      while ((pid = fork()) == -1 && (errno == EAGAIN || errno == ENOMEM))
	sleep(2);

      if (pid == -1)
        {
	  if (!option_bool(OPT_DEBUG))
	    {
	      close(pipeout[0]);
	      close(pipeout[1]);
	    }
	  continue;
        }
      
      /* wait for child to complete */
      if (pid != 0)
	{
	  if (!option_bool(OPT_DEBUG))
	    {
	      FILE *fp;
	  
	      close(pipeout[1]);
	      
	      /* Read lines sent to stdout/err by the script and pass them back to be logged */
	      if (!(fp = fdopen(pipeout[0], "r")))
		close(pipeout[0]);
	      else
		{
		  while (fgets(daemon->packet, daemon->packet_buff_sz, fp))
		    {
		      /* do not include new lines, log will append them */
		      size_t len = strlen(daemon->packet);
		      if (len > 0)
			{
			  --len;
			  if (daemon->packet[len] == '\n')
			    daemon->packet[len] = 0;
			}
		      send_event(event_fd, EVENT_SCRIPT_LOG, 0, daemon->packet);
		    }
		  fclose(fp);
		}
	    }
	  
	  /* reap our children's children, if necessary */
	  while (1)
	    {
	      int status;
	      pid_t rc = wait(&status);
	      
	      if (rc == pid)
		{
		  /* On error send event back to main process for logging */
		  if (WIFSIGNALED(status))
		    send_event(event_fd, EVENT_KILLED, WTERMSIG(status), NULL);
		  else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
		    send_event(event_fd, EVENT_EXITED, WEXITSTATUS(status), NULL);
		  break;
		}
	      
	      if (rc == -1 && errno != EINTR)
		break;
	    }
	  
	  continue;
	}

      if (!option_bool(OPT_DEBUG))
	{
	  /* map stdout/stderr of script to pipeout */
	  close(pipeout[0]);
	  dup2(pipeout[1], STDOUT_FILENO);
	  dup2(pipeout[1], STDERR_FILENO);
	  close(pipeout[1]);
	}
      
      if (data.action != ACTION_TFTP && data.action != ACTION_ARP && data.action != ACTION_RELAY_SNOOP)
	{
#ifdef HAVE_DHCP6
	  my_setenv("DNSMASQ_IAID", is6 ? daemon->dhcp_buff3 : NULL, &err);
	  my_setenv("DNSMASQ_SERVER_DUID", is6 ? daemon->dhcp_packet.iov_base : NULL, &err); 
	  my_setenv("DNSMASQ_MAC", is6 && data.hwaddr_len != 0 ? daemon->dhcp_buff : NULL, &err);
#endif
	  
	  my_setenv("DNSMASQ_CLIENT_ID", !is6 && data.clid_len != 0 ? daemon->packet : NULL, &err);
	  my_setenv("DNSMASQ_INTERFACE", strlen(data.interface) != 0 ? data.interface : NULL, &err);
	  
#ifdef HAVE_BROKEN_RTC
	  sprintf(daemon->dhcp_buff2, "%u", data.length);
	  my_setenv("DNSMASQ_LEASE_LENGTH", daemon->dhcp_buff2, &err);
#else
	  sprintf(daemon->dhcp_buff2, "%lu", (unsigned long)data.expires);
	  my_setenv("DNSMASQ_LEASE_EXPIRES", daemon->dhcp_buff2, &err); 
#endif
	  
	  my_setenv("DNSMASQ_DOMAIN", domain, &err);
	  
	  end = extradata + data.ed_len;
	  buf = extradata;

	  if (data.ed_len == 0)
	    my_setenv("DNSMASQ_DATA_MISSING", "1", &err);
	  
	  if (!is6)
	    buf = grab_extradata(buf, end, "DNSMASQ_VENDOR_CLASS", &err);
#ifdef HAVE_DHCP6
	  else
	    {
	      if (data.vendorclass_count != 0)
		{
		  buf = grab_extradata(buf, end, "DNSMASQ_VENDOR_CLASS_ID", &err);
		  for (i = 0; i < data.vendorclass_count - 1; i++)
		    {
		      sprintf(daemon->dhcp_buff2, "DNSMASQ_VENDOR_CLASS%i", i);
		      buf = grab_extradata(buf, end, daemon->dhcp_buff2, &err);
		    }
		}
	    }
#endif
	  
	  buf = grab_extradata(buf, end, "DNSMASQ_SUPPLIED_HOSTNAME", &err);
	  
	  if (!is6)
	    {
	      buf = grab_extradata(buf, end, "DNSMASQ_CPEWAN_OUI", &err);
	      buf = grab_extradata(buf, end, "DNSMASQ_CPEWAN_SERIAL", &err);   
	      buf = grab_extradata(buf, end, "DNSMASQ_CPEWAN_CLASS", &err);
	      buf = grab_extradata(buf, end, "DNSMASQ_CIRCUIT_ID", &err);
	      buf = grab_extradata(buf, end, "DNSMASQ_SUBSCRIBER_ID", &err);
	      buf = grab_extradata(buf, end, "DNSMASQ_REMOTE_ID", &err);
	      buf = grab_extradata(buf, end, "DNSMASQ_REQUESTED_OPTIONS", &err);
	    }
	  
	  buf = grab_extradata(buf, end, "DNSMASQ_TAGS", &err);

	  if (is6)
	    buf = grab_extradata(buf, end, "DNSMASQ_RELAY_ADDRESS", &err);
	  else
	    {
	      const char *giaddr = NULL;
	      if (data.giaddr.s_addr != 0)
		  giaddr = inet_ntop(AF_INET, &data.giaddr, daemon->dhcp_buff2, ADDRSTRLEN);
	      my_setenv("DNSMASQ_RELAY_ADDRESS", giaddr, &err);
	    }
	  
	  for (i = 0; buf; i++)
	    {
	      sprintf(daemon->dhcp_buff2, "DNSMASQ_USER_CLASS%i", i);
	      buf = grab_extradata(buf, end, daemon->dhcp_buff2, &err);
	    }
	  
	  sprintf(daemon->dhcp_buff2, "%u", data.remaining_time);
	  my_setenv("DNSMASQ_TIME_REMAINING", data.action != ACTION_DEL && data.remaining_time != 0 ? daemon->dhcp_buff2 : NULL, &err);
	  
	  my_setenv("DNSMASQ_OLD_HOSTNAME", data.action == ACTION_OLD_HOSTNAME ? hostname : NULL, &err);
	  if (data.action == ACTION_OLD_HOSTNAME)
	    hostname = NULL;
	  
	  my_setenv("DNSMASQ_LOG_DHCP", option_bool(OPT_LOG_OPTS) ? "1" : NULL, &err);
	}
      
      /* we need to have the event_fd around if exec fails */
      if ((i = fcntl(event_fd, F_GETFD)) != -1)
	fcntl(event_fd, F_SETFD, i | FD_CLOEXEC);
      close(pipefd[0]);

      if (data.action == ACTION_RELAY_SNOOP)
	strcpy(daemon->packet, data.interface);
      
      p =  strrchr(daemon->lease_change_command, '/');
      if (err == 0)
	{
	  execl(daemon->lease_change_command, 
		p ? p+1 : daemon->lease_change_command, action_str, 
		(is6 && data.action != ACTION_ARP) ? daemon->packet : daemon->dhcp_buff, 
		daemon->addrbuff, hostname, (char*)NULL);
	  err = errno;
	}
      /* failed, send event so the main process logs the problem */
      send_event(event_fd, EVENT_EXEC_ERR, err, NULL);
      _exit(0); 
    }
}

/**
 * @brief Set or unset environment variable for script execution
 * 
 * @detailed
 * Wrapper around setenv/unsetenv that tracks errors via an error flag. If value is NULL,
 * the environment variable is removed; otherwise it is set to the given value. Once an
 * error occurs (*error != 0), subsequent calls do nothing to prevent cascading failures.
 * This allows batch setting of environment variables with single error check at the end.
 * 
 * @param name Environment variable name (e.g., "DNSMASQ_LEASE_EXPIRES")
 * @param value Value to set, or NULL to unset the variable
 * @param error Pointer to error flag, set to errno if setenv fails
 * 
 * @return void (errors reported via error parameter)
 * 
 * @note If *error is already non-zero, function returns immediately without action
 * @note Used to set DNSMASQ_* environment variables before execl() of script
 * 
 * @warning Does not validate name or value parameters, caller must ensure validity
 * 
 * @see grab_extradata() which uses this to set DHCP option data
 * @see execl() call at line 678 which executes script with these environment variables
 * 
 * EXAMPLE USAGE:
 * @code
 * int err = 0;
 * my_setenv("DNSMASQ_LEASE_EXPIRES", "1234567890", &err);
 * my_setenv("DNSMASQ_DOMAIN", "example.com", &err);
 * if (err != 0) {
 *   send_event(event_fd, EVENT_EXEC_ERR, err, NULL);
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * Modifies process environment via setenv() or unsetenv(), affecting subsequent execl().
 * 
 * THREAD SAFETY:
 * Not thread-safe due to environment modification. Safe in helper's single-threaded context
 * during script setup phase before exec.
 */
static void my_setenv(const char *name, const char *value, int *error)
{
  if (*error == 0)
    {
      if (!value)
	unsetenv(name);
      else if (setenv(name, value, 1) != 0)
	*error = errno;
    }
}

/**
 * @brief Extract null-terminated string from buffer and set as environment variable
 * 
 * @detailed
 * Parses a null-terminated string from a buffer containing concatenated DHCP option data,
 * removes any '=' characters (to prevent environment variable injection attacks), and sets
 * the specified environment variable to the extracted value. Returns pointer to next data
 * in buffer or NULL if end reached. Used to extract vendor class, client ID, circuit ID,
 * and other DHCP options from lease extradata for script access.
 * 
 * @param buf Pointer to current position in extradata buffer
 * @param end Pointer to end of extradata buffer (one past last valid byte)
 * @param env Environment variable name to set (e.g., "DNSMASQ_VENDOR_CLASS")
 * @param err Pointer to error flag for my_setenv
 * 
 * @return Pointer to next string in buffer (after null terminator), or NULL if end reached
 * @retval NULL No more data available in buffer
 * @retval non-NULL Pointer to start of next string in buffer
 * 
 * @note Strips '=' characters from extracted value for security (prevents env injection)
 * @note If buf equals end, returns NULL immediately without processing
 * 
 * @warning Assumes buf points to valid null-terminated string within bounds
 * @warning Modifies buffer content by overwriting '=' with null terminators
 * 
 * @see queue_script() which packs extradata into the buffer
 * @see my_setenv() which performs actual environment variable setting
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = extradata;
 * int err = 0;
 * p = grab_extradata(p, extradata + ed_len, "DNSMASQ_VENDOR_CLASS", &err);
 * p = grab_extradata(p, extradata + ed_len, "DNSMASQ_CIRCUIT_ID", &err);
 * // p is now NULL if all data consumed
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Modifies buffer by replacing '=' with null terminator if found
 * - Sets environment variable via my_setenv()
 * 
 * THREAD SAFETY:
 * Not thread-safe due to buffer modification and environment changes. Safe in helper's
 * single-threaded context before script execution.
 */
static unsigned char *grab_extradata(unsigned char *buf, unsigned char *end,  char *env, int *err)
{
  unsigned char *next = NULL;
  char *val = NULL;

  if (buf && (buf != end))
    {
      for (next = buf; ; next++)
	if (next == end)
	  {
	    next = NULL;
	    break;
	  }
	else if (*next == 0)
	  break;

      if (next && (next != buf))
	{
	  char *p;
	  /* No "=" in value */
	  if ((p = strchr((char *)buf, '=')))
	    *p = 0;
	  val = (char *)buf;
	}
    }
  
  my_setenv(env, val, err);
   
  return next ? next + 1 : NULL;
}

#ifdef HAVE_LUASCRIPT
/**
 * @brief Extract null-terminated string from buffer and add to Lua table
 * 
 * @detailed
 * Similar to grab_extradata() but for Lua integration. Parses a null-terminated string
 * from extradata buffer and adds it as a field to the Lua table currently on top of the
 * Lua stack. Used to populate the data table passed to Lua lease() function with DHCP
 * option values. Does not modify buffer content or strip characters like grab_extradata().
 * 
 * @param buf Pointer to current position in extradata buffer
 * @param end Pointer to end of extradata buffer
 * @param field Lua table field name (e.g., "vendor_class", "circuit_id")
 * 
 * @return Pointer to next string in buffer (after null terminator), or NULL if end reached
 * @retval NULL Buffer exhausted or buf equals end
 * @retval non-NULL Pointer to start of next string
 * 
 * @note Requires Lua table to be on top of stack (index -2 after push operations)
 * @note Empty strings (buf == next after finding null) are not added to table
 * 
 * @warning Assumes buf points within valid buffer bounds
 * @warning Caller must ensure Lua stack has room for push operations
 * 
 * @see grab_extradata() for environment variable version
 * @see Lua lease() function called at line 493 which receives the populated table
 * 
 * EXAMPLE USAGE:
 * @code
 * lua_newtable(lua);  // Create data table
 * unsigned char *p = extradata;
 * p = grab_extradata_lua(p, extradata + ed_len, "vendor_class");
 * p = grab_extradata_lua(p, extradata + ed_len, "circuit_id");
 * lua_call(lua, 2, 0);  // Call with action and data table
 * @endcode
 * 
 * SIDE EFFECTS:
 * Modifies Lua stack by pushing string and setting table field via lua_pushstring() and
 * lua_setfield().
 * 
 * THREAD SAFETY:
 * Not thread-safe, requires exclusive access to Lua state. Safe in helper's single-threaded
 * event processing loop.
 */
static unsigned char *grab_extradata_lua(unsigned char *buf, unsigned char *end, char *field)
{
  unsigned char *next;

  if (!buf || (buf == end))
    return NULL;

  for (next = buf; *next != 0; next++)
    if (next == end)
      return NULL;
  
  if (next != buf)
    {
      lua_pushstring(lua,  (char *)buf);
      lua_setfield(lua, -2, field);
    }

  return next + 1;
}
#endif

/**
 * @brief Allocate or grow global event buffer for helper communication
 * 
 * @detailed
 * Ensures the global static buffer (buf) is at least the requested size, reallocating
 * if necessary. Uses whine_malloc() which logs allocation failures. Sets minimum size
 * of sizeof(struct script_data) + 200 bytes for typical small events. The buffer is
 * reused across multiple events to avoid frequent allocations. Only grows, never shrinks.
 * 
 * @param size Minimum required buffer size in bytes
 * 
 * @return void (allocation failure is silent, checked by caller via buf != NULL)
 * 
 * @note Buffer is never freed, grows to accommodate largest event seen
 * @note Minimum allocation is sizeof(struct script_data) + 200 bytes
 * @note Uses static globals: buf, buf_size (both modified by this function)
 * 
 * @warning If allocation fails, buf may be NULL and operations will fail
 * @warning Frees old buffer before allocating new, brief period where buf is invalid
 * 
 * @see queue_script() which calls this to ensure buffer space for lease events
 * @see queue_tftp() which calls this for TFTP events
 * @see queue_arp() which calls this for ARP events
 * 
 * EXAMPLE USAGE:
 * @code
 * size_t needed = sizeof(struct script_data) + hostname_len + clid_len + ed_len;
 * buff_alloc(needed);
 * if (buf != NULL) {
 *   // Safe to use buf up to buf_size bytes
 *   buf->action = ACTION_ADD;
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Modifies global variables: buf (reallocated), buf_size (updated)
 * - May free previous buffer via free()
 * - Allocates memory via whine_malloc() which may log to syslog on failure
 * 
 * THREAD SAFETY:
 * Not thread-safe due to modification of static globals. Safe in main daemon's single-
 * threaded event-driven architecture where queue_* functions are called from main loop.
 */
static void buff_alloc(size_t size)
{
  if (size > buf_size)
    {
      struct script_data *new;
      
      /* start with reasonable size, will almost never need extending. */
      if (size < sizeof(struct script_data) + 200)
	size = sizeof(struct script_data) + 200;

      if (!(new = whine_malloc(size)))
	return;
      if (buf)
	free(buf);
      buf = new;
      buf_size = size;
    }
}

/**
 * @brief Serialize DHCP lease event data for transmission to helper process
 * 
 * @detailed
 * Packs DHCP lease change information into the global buffer for subsequent transmission
 * to the helper process via helper_write(). Serializes struct dhcp_lease fields, optional
 * hostname, client ID, and extradata (DHCP options) into struct script_data wire format.
 * Handles both DHCPv4 and DHCPv6 leases, including IPv6-specific fields like IAID and
 * vendorclass_count. Calculates remaining time until lease expiry for script use.
 * 
 * @param action Event type: ACTION_ADD, ACTION_DEL, ACTION_OLD, ACTION_OLD_HOSTNAME
 * @param lease Pointer to DHCP lease structure containing lease details
 * @param hostname Optional hostname associated with lease, NULL if none
 * @param now Current time for calculating remaining lease time
 * 
 * @return void (queues event in buffer, call helper_write() to transmit)
 * 
 * @note Returns immediately if daemon->helperfd == -1 (no helper configured)
 * @note Uses daemon->dhcpfd or daemon->dhcp6fd to determine interface names
 * @note For DHCPv6 leases, copies addr6 and IAID; for DHCPv4, uses addr
 * 
 * @warning Assumes lease pointer is valid and points to initialized dhcp_lease
 * @warning Buffer overflow possible if hostname + clid + extradata exceed buffer
 * 
 * @see helper_write() to transmit queued event to helper process
 * @see struct dhcp_lease in dnsmasq.h for lease structure definition
 * @see ACTION_* constants in dnsmasq.h for event types
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease_find_by_client(...);
 * queue_script(ACTION_ADD, lease, "client-hostname", time(NULL));
 * helper_write();  // Flush to helper process
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements lease notification mechanism supporting RFC 2131 (DHCPv4) state changes
 * and RFC 3315 (DHCPv6) binding lifecycle events.
 * 
 * SIDE EFFECTS:
 * - Modifies global buffer (buf) via buff_alloc() and direct writes
 * - Updates bytes_in_buf to reflect queued data size
 * - May allocate/reallocate global buffer if current size insufficient
 * 
 * THREAD SAFETY:
 * Not thread-safe, modifies static global buffer. Safe in single-threaded event-driven
 * main loop where DHCP events are processed sequentially.
 */
void queue_script(int action, struct dhcp_lease *lease, char *hostname, time_t now)
{
  unsigned char *p;
  unsigned int hostname_len = 0, clid_len = 0, ed_len = 0;
  int fd = daemon->dhcpfd;
#ifdef HAVE_DHCP6 
  if (!daemon->dhcp)
    fd = daemon->dhcp6fd;
#endif

  /* no script */
  if (daemon->helperfd == -1)
    return;

  if (lease->extradata)
    ed_len = lease->extradata_len;
  if (lease->clid)
    clid_len = lease->clid_len;
  if (hostname)
    hostname_len = strlen(hostname) + 1;

  buff_alloc(sizeof(struct script_data) +  clid_len + ed_len + hostname_len);

  buf->action = action;
  buf->flags = lease->flags;
#ifdef HAVE_DHCP6 
  buf->vendorclass_count = lease->vendorclass_count;
  buf->addr6 = lease->addr6;
  buf->iaid = lease->iaid;
#endif
  buf->hwaddr_len = lease->hwaddr_len;
  buf->hwaddr_type = lease->hwaddr_type;
  buf->clid_len = clid_len;
  buf->ed_len = ed_len;
  buf->hostname_len = hostname_len;
  buf->addr = lease->addr;
  buf->giaddr = lease->giaddr;
  memcpy(buf->hwaddr, lease->hwaddr, DHCP_CHADDR_MAX);
  if (!indextoname(fd, lease->last_interface, buf->interface))
    buf->interface[0] = 0;
  
#ifdef HAVE_BROKEN_RTC 
  buf->length = lease->length;
#else
  buf->expires = lease->expires;
#endif

  if (lease->expires != 0)
    buf->remaining_time = (unsigned int)difftime(lease->expires, now);
  else
    buf->remaining_time = 0;

  p = (unsigned char *)(buf+1);
  if (clid_len != 0)
    {
      memcpy(p, lease->clid, clid_len);
      p += clid_len;
    }
  if (hostname_len != 0)
    {
      memcpy(p, hostname, hostname_len);
      p += hostname_len;
    }
  if (ed_len != 0)
    {
      memcpy(p, lease->extradata, ed_len);
      p += ed_len;
    }
  bytes_in_buf = p - (unsigned char *)buf;
}

#ifdef HAVE_DHCP6
/**
 * @brief Queue DHCPv6 relay snooping event for helper notification
 * 
 * @detailed
 * Serializes DHCPv6 relay agent snooping information for transmission to helper process.
 * Used when dnsmasq observes DHCPv6 messages relayed through it, allowing scripts to
 * track client prefixes and delegations. Formats prefix in CIDR notation (e.g., 
 * "2001:db8::/64") and includes client address and interface information. This enables
 * external scripts to perform actions based on prefix delegation events.
 * 
 * @param client IPv6 address of DHCPv6 client
 * @param if_index Interface index where relay message was received
 * @param prefix IPv6 prefix being delegated or assigned
 * @param prefix_len Prefix length in bits (e.g., 64 for /64)
 * 
 * @return void (queues event, call helper_write() to transmit)
 * 
 * @note Returns immediately if daemon->helperfd == -1 (no helper process)
 * @note Uses ACTION_RELAY_SNOOP action type
 * @note Prefix formatted as "address/length" string in hostname field
 * 
 * @warning Requires HAVE_DHCP6 compile-time option
 * @warning Assumes prefix points to valid in6_addr structure
 * 
 * @see helper_write() to flush queued event
 * @see Lua snoop() function which receives this event (lines 340-357)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr client_addr, delegated_prefix;
 * // ... extract from relay message ...
 * queue_relay_snoop(&client_addr, if_index, &delegated_prefix, 64);
 * helper_write();
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Supports RFC 3315 Section 20 relay agent behavior monitoring for prefix delegation
 * tracking and external logging.
 * 
 * SIDE EFFECTS:
 * - Modifies global buffer via buff_alloc() and direct writes
 * - Updates bytes_in_buf
 * - Uses daemon->addrbuff for prefix formatting
 * 
 * THREAD SAFETY:
 * Not thread-safe, modifies static global buffer. Safe in single-threaded DHCPv6
 * packet processing context.
 */
void queue_relay_snoop(struct in6_addr *client, int if_index, struct in6_addr *prefix, int prefix_len)
{
  /* no script */
  if (daemon->helperfd == -1)
    return;
  
  inet_ntop(AF_INET6, prefix, daemon->addrbuff, ADDRSTRLEN);

  /* 5 for /nnn and zero on the end of the prefix. */
  buff_alloc(sizeof(struct script_data) + ADDRSTRLEN + 5);
  memset(buf, 0, sizeof(struct script_data));

  buf->action = ACTION_RELAY_SNOOP;
  buf->addr6 = *client;
  buf->hostname_len = sprintf((char *)(buf+1), "%s/%u", daemon->addrbuff, prefix_len) + 1;
  
  indextoname(daemon->dhcp6fd, if_index, buf->interface);

  bytes_in_buf = sizeof(struct script_data) + buf->hostname_len;
}
#endif

#ifdef HAVE_TFTP
/**
 * @brief Queue TFTP file transfer event for helper notification
 * 
 * @detailed
 * Serializes TFTP file transfer completion information for transmission to helper process.
 * Notifies scripts when TFTP files are successfully transferred, providing filename, peer
 * address (IPv4 or IPv6), and file size. Reuses DHCP wire format fields for efficiency:
 * hostname field contains filename, file_len contains transfer size, addr/addr6 contains
 * peer address. This allows monitoring of PXE boot activity and file distribution.
 * 
 * @param file_len Size of transferred file in bytes (off_t for large file support)
 * @param filename Name of file transferred (relative to TFTP root)
 * @param peer Socket address of TFTP client (IPv4 or IPv6)
 * 
 * @return void (queues event, call helper_write() to transmit)
 * 
 * @note Returns immediately if daemon->helperfd == -1 (no helper)
 * @note Uses ACTION_TFTP action type
 * @note Supports both AF_INET and AF_INET6 peer addresses
 * @note Comment line 869 notes "nasty reuse" of DHCP fields for TFTP data
 * 
 * @warning Requires HAVE_TFTP compile-time option
 * @warning Assumes filename is null-terminated and peer is valid sockaddr union
 * 
 * @see helper_write() to flush event
 * @see Lua tftp() function (lines 322-338) which receives this event
 * @see tftp.c for TFTP server implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr client_addr;
 * off_t size = 1024;
 * queue_tftp(size, "pxelinux.0", &client_addr);
 * helper_write();
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Provides notification mechanism for RFC 1350 (TFTP) file transfers, enabling external
 * logging and monitoring of boot file distribution.
 * 
 * SIDE EFFECTS:
 * - Modifies global buffer via buff_alloc() and direct writes
 * - Updates bytes_in_buf
 * - Repurposes struct script_data fields for TFTP-specific data
 * 
 * THREAD SAFETY:
 * Not thread-safe, modifies static buffer. Safe in single-threaded TFTP transfer
 * completion context.
 */
void queue_tftp(off_t file_len, char *filename, union mysockaddr *peer)
{
  unsigned int filename_len;

  /* no script */
  if (daemon->helperfd == -1)
    return;
  
  filename_len = strlen(filename) + 1;
  buff_alloc(sizeof(struct script_data) +  filename_len);
  memset(buf, 0, sizeof(struct script_data));

  buf->action = ACTION_TFTP;
  buf->hostname_len = filename_len;
  buf->file_len = file_len;

  if ((buf->flags = peer->sa.sa_family) == AF_INET)
    buf->addr = peer->in.sin_addr;
  else
    buf->addr6 = peer->in6.sin6_addr;

  memcpy((unsigned char *)(buf+1), filename, filename_len);
  
  bytes_in_buf = sizeof(struct script_data) +  filename_len;
}
#endif

/**
 * @brief Queue ARP or NDP detection event for helper notification
 * 
 * @detailed
 * Serializes ARP (IPv4) or NDP (IPv6 Neighbor Discovery) address detection events for
 * transmission to helper process. Used to notify scripts when addresses are detected via
 * ARP or NDP, even without DHCP lease. Supports both ACTION_ARP (add) and ACTION_ARP_DEL
 * (delete) events. Allows external tracking of network topology and address usage beyond
 * DHCP-managed addresses.
 * 
 * @param action Event type: ACTION_ARP for add, ACTION_ARP_DEL for delete
 * @param mac MAC address of detected device
 * @param maclen Length of MAC address in bytes (typically 6 for Ethernet)
 * @param family Address family: AF_INET for IPv4, AF_INET6 for IPv6
 * @param addr IP address detected via ARP/NDP
 * 
 * @return void (queues event, call helper_write() to transmit)
 * 
 * @note Returns immediately if daemon->helperfd == -1 (no helper)
 * @note MAC address type always set to ARPHRD_ETHER (Ethernet)
 * @note Both IPv4 (ARP) and IPv6 (NDP) addresses supported via family parameter
 * 
 * @warning Assumes mac buffer contains at least maclen valid bytes
 * @warning Assumes addr points to valid all_addr union
 * 
 * @see helper_write() to flush event
 * @see Lua arp() function (lines 358-373) which receives this event
 * @see arp.c for ARP table monitoring implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char hwaddr[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * union all_addr ip_addr;
 * ip_addr.addr4.s_addr = inet_addr("192.168.1.100");
 * queue_arp(ACTION_ARP, hwaddr, 6, AF_INET, &ip_addr);
 * helper_write();
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Supports monitoring of RFC 826 (ARP) and RFC 4861 (NDP) address resolution for
 * network topology tracking.
 * 
 * SIDE EFFECTS:
 * - Modifies global buffer via buff_alloc() and direct writes
 * - Updates bytes_in_buf
 * - Sets buffer size to sizeof(struct script_data)
 * 
 * THREAD SAFETY:
 * Not thread-safe, modifies static buffer. Safe in single-threaded ARP/NDP event
 * processing context.
 */
void queue_arp(int action, unsigned char *mac, int maclen, int family, union all_addr *addr)
{
  /* no script */
  if (daemon->helperfd == -1)
    return;
  
  buff_alloc(sizeof(struct script_data));
  memset(buf, 0, sizeof(struct script_data));

  buf->action = action;
  buf->hwaddr_len = maclen;
  buf->hwaddr_type =  ARPHRD_ETHER; 
  if ((buf->flags = family) == AF_INET)
    buf->addr = addr->addr4;
  else
    buf->addr6 = addr->addr6;
  
  memcpy(buf->hwaddr, mac, maclen);
  
  bytes_in_buf = sizeof(struct script_data);
}

/**
 * @brief Check if helper event buffer is empty
 * 
 * @detailed
 * Returns whether the global event buffer has any pending data to transmit to the helper
 * process. Used by main daemon to determine if helper_write() needs to be called, typically
 * checked after queuing events or when helper socket becomes writable. Zero bytes indicates
 * no events queued, non-zero indicates data waiting for transmission.
 * 
 * @return Boolean indicating buffer empty state
 * @retval 1 (true) Buffer is empty, no events queued
 * @retval 0 (false) Buffer contains event data awaiting transmission
 * 
 * @note Thread-safe read of bytes_in_buf counter (single value read)
 * @note Typically called before select/poll on helper fd to determine write monitoring
 * 
 * @see helper_write() which transmits buffered events
 * @see queue_script(), queue_tftp(), queue_arp() which populate buffer
 * 
 * EXAMPLE USAGE:
 * @code
 * queue_script(ACTION_ADD, lease, hostname, now);
 * if (!helper_buf_empty()) {
 *   helper_write();  // Flush pending events
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * None, read-only check of global variable bytes_in_buf.
 * 
 * THREAD SAFETY:
 * Thread-safe for read (single integer read is atomic on most architectures). Safe in
 * single-threaded event loop where it's used.
 */
int helper_buf_empty(void)
{
  return bytes_in_buf == 0;
}

/**
 * @brief Transmit queued event data to helper process
 * 
 * @detailed
 * Writes buffered event data to helper process via daemon->helperfd socket. Performs
 * non-blocking write, handling partial writes by moving remaining data to buffer start.
 * Called from main event loop when helper socket is writable and buffer contains data.
 * Handles EAGAIN/EINTR gracefully for non-blocking I/O, clears buffer on other errors
 * (likely helper process terminated).
 * 
 * @return void (errors clear buffer, caller should check helper_buf_empty())
 * 
 * @note Returns immediately if bytes_in_buf is 0 (no data to send)
 * @note Uses write() system call which may return partial write
 * @note On partial write, memmove() shifts remaining data to buffer start
 * @note On EAGAIN/EINTR, preserves buffer for retry on next writable event
 * @note On other errors, clears buffer (assumes helper dead, event lost)
 * 
 * @warning Assumes daemon->helperfd is valid and open
 * @warning Data loss possible if helper terminates (bytes_in_buf set to 0)
 * 
 * @see helper_buf_empty() to check if data remains after write
 * @see queue_script(), queue_tftp(), queue_arp() which populate buffer
 * @see create_helper() which creates daemon->helperfd socket
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main event loop when helper fd is writable
 * if (poll_check(daemon->helperfd, POLLOUT) && !helper_buf_empty()) {
 *   helper_write();
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Transport mechanism for RFC 2131 (DHCPv4) and RFC 3315 (DHCPv6) lease event
 * notifications to external scripts.
 * 
 * SIDE EFFECTS:
 * - Writes data to daemon->helperfd socket
 * - Modifies global buffer via memmove() on partial write
 * - Updates bytes_in_buf to reflect remaining data
 * - May clear buffer (set bytes_in_buf = 0) on write errors
 * 
 * THREAD SAFETY:
 * Not thread-safe, modifies static buffer and performs I/O. Safe in single-threaded
 * event loop where called from main daemon.
 */
void helper_write(void)
{
  ssize_t rc;

  if (bytes_in_buf == 0)
    return;
  
  if ((rc = write(daemon->helperfd, buf, bytes_in_buf)) != -1)
    {
      if (bytes_in_buf != (size_t)rc)
	memmove(buf, buf + rc, bytes_in_buf - rc); 
      bytes_in_buf -= rc;
    }
  else
    {
      if (errno == EAGAIN || errno == EINTR)
	return;
      bytes_in_buf = 0;
    }
}

#endif /* HAVE_SCRIPT */
