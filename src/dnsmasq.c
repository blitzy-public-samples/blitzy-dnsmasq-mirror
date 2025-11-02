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
 * @file dnsmasq.c
 * @brief Main daemon entry point, initialization, and event loop orchestration
 * 
 * DETAILED PURPOSE:
 * 
 * This file implements the core daemon functionality for dnsmasq, a lightweight DNS forwarder,
 * DHCP server, and network boot server. It contains the main() entry point which handles
 * initialization, privilege management, and enters the primary event loop that coordinates
 * all network services.
 * 
 * The daemon implements a single-process, cooperative multitasking architecture using poll()-based
 * event multiplexing. After parsing configuration and creating all necessary sockets, the daemon
 * drops privileges (setuid/setgid to configured --user, Linux capabilities reduced from
 * CAP_NET_ADMIN → CAP_NET_BIND_SERVICE → CAP_NET_RAW for DHCP functionality), optionally forks
 * to background (unless --no-daemon), writes PID file, and installs signal handlers using the
 * self-pipe pattern for async-signal-safe operation.
 * 
 * The main event loop (lines 1056-1287) polls file descriptors for all enabled services including:
 * DNS (port 53), DHCP (ports 67/68), DHCPv6 (ports 547/546), TFTP (port 69), netlink/routing
 * sockets for interface changes, D-Bus/ubus for IPC, and a self-pipe for signal handling. When
 * events occur, they are dispatched to the appropriate subsystem handlers: check_dns_listeners()
 * dispatches DNS packets to forward.c receive_query(), check_dhcp_listeners() dispatches DHCP
 * packets to dhcp.c dhcp_packet(), etc.
 * 
 * KEY RESPONSIBILITIES:
 * 
 * - main() - Daemon initialization sequence, configuration parsing, socket creation, privilege
 *   management, daemonization, signal handler installation, and entering main event loop
 * - check_dns_listeners() - Dispatches incoming DNS queries from network sockets to forward.c
 *   receive_query() for processing
 * - sig_handler() - POSIX signal handler implementing self-pipe pattern for async-signal-safe
 *   signal queueing to main loop
 * - async_event() - Processes queued signals in main loop context including SIGHUP (reload config),
 *   SIGUSR1 (dump cache stats), SIGUSR2 (rotate logs), SIGTERM/SIGINT (graceful shutdown)
 * - clear_cache_and_reload() - Flushes DNS cache and reloads configuration files (hosts, resolv.conf)
 *   in response to SIGHUP signal
 * 
 * DEPENDENCIES:
 * 
 * Includes: dnsmasq.h (primary type definitions including struct daemon), config.h (compile-time
 * configuration constants and feature macros), locale.h (for IDN/i18n support)
 * 
 * Called by: Operating system (program entry point), signal handlers (async context)
 * 
 * Calls: option.c read_opts() for configuration parsing, network.c create_bound_listeners() for
 * socket setup, forward.c receive_query() for DNS query processing, dhcp.c dhcp_packet() for DHCP
 * request processing, helper.c create_helper() for privilege-separated script execution, poll.c
 * do_poll() for event multiplexing
 * 
 * DATA STRUCTURES:
 * 
 * - struct daemon *daemon (global, line 27) - Central daemon state container holding all
 *   configuration, runtime state, socket file descriptors, and pointers to data structures for
 *   DNS cache, DHCP leases, upstream servers, etc. (defined in dnsmasq.h ~line 800-1100)
 * - struct sigaction sigact (main(), line 43) - POSIX signal handler configuration structure
 * - struct event_desc (async_event(), line 1451) - Event descriptor for self-pipe signal delivery
 * 
 * COMPILE-TIME OPTIONS:
 * 
 * This file's behavior is controlled by numerous feature macros tested throughout:
 * - HAVE_DHCP - Enables DHCPv4 server functionality (affects socket creation, event dispatch)
 * - HAVE_DHCP6 - Enables DHCPv6 server and Router Advertisement (affects socket creation)
 * - HAVE_TFTP - Enables TFTP server functionality
 * - HAVE_DBUS - Enables D-Bus IPC interface for runtime configuration
 * - HAVE_UBUS - Enables ubus IPC interface (OpenWrt)
 * - HAVE_SCRIPT - Enables lease-change script execution via helper process
 * - HAVE_LUASCRIPT - Enables Lua scripting support (implies HAVE_SCRIPT)
 * - HAVE_DNSSEC - Enables DNSSEC validation (affects cache and forwarding behavior)
 * - HAVE_AUTH - Enables authoritative DNS server functionality
 * - HAVE_INOTIFY - Uses Linux inotify for automatic config file reload detection
 * - HAVE_LINUX_NETWORK - Linux-specific networking (capabilities, netlink, SO_BINDTODEVICE)
 * - HAVE_BSD_NETWORK - BSD-specific networking (routing socket, interface enumeration)
 * - HAVE_SOLARIS_NETWORK - Solaris-specific networking
 * - HAVE_IDN, HAVE_LIBIDN2 - Internationalized Domain Name support
 * - LOCALEDIR - Enables gettext localization
 * 
 * See config.h for full list of compile-time configuration options.
 * 
 * THREADING/CONCURRENCY MODEL:
 * 
 * dnsmasq uses a single-process, single-threaded, cooperative multitasking model based on poll()-
 * based event multiplexing. It is NOT thread-safe and MUST NOT be used in multithreaded contexts.
 * Signal handlers use the self-pipe pattern to avoid race conditions: async-signal-safe write()
 * to pipe in signal context, with actual signal processing deferred to main loop via async_event().
 * 
 * For TCP DNS queries, child processes are forked (up to MAX_PROCS=20) to handle long-lived
 * connections without blocking the main event loop. Child processes are tracked in daemon->tcp_pids[]
 * array and reaped via SIGCHLD handler.
 * 
 * For script execution, a single helper process is forked before dropping root privileges,
 * communicating via pipe with privilege-separated script invocation (see helper.c).
 * 
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/ARCHITECTURE.md for system architecture overview and event loop details
 * @see forward.c for DNS query forwarding implementation
 * @see dhcp.c for DHCP server implementation
 * @see poll.c for poll() wrapper and event multiplexing
 */

/* Declare static char *compiler_opts  in config.h */
#define DNSMASQ_COMPILE_OPTS

/* dnsmasq.h has to be included first as it sources config.h */
#include "dnsmasq.h"

#if defined(HAVE_IDN) || defined(HAVE_LIBIDN2) || defined(LOCALEDIR)
#include <locale.h>
#endif

struct daemon *daemon;

static volatile pid_t pid = 0;
static volatile int pipewrite;

static void set_dns_listeners(void);
static void check_dns_listeners(time_t now);
static void sig_handler(int sig);
static void async_event(int pipe, time_t now);
static void fatal_event(struct event_desc *ev, char *msg);
static int read_event(int fd, struct event_desc *evp, char **msg);
static void poll_resolv(int force, int do_reload, time_t now);

/**
 * @brief Initialize dnsmasq daemon and enter main event loop
 * 
 * @detailed
 * This is the main entry point for the dnsmasq daemon. It performs complete initialization sequence:
 * parses command-line arguments and configuration files via read_opts(), allocates and initializes
 * the global daemon state structure, creates all necessary network sockets (DNS, DHCP, TFTP, netlink),
 * optionally forks a helper process for privilege-separated script execution, drops privileges to
 * configured user/group (default "nobody"), optionally daemonizes to background, writes PID file,
 * installs signal handlers, and enters the main event loop which polls sockets and dispatches events
 * to subsystem handlers until termination signal received (SIGTERM/SIGINT).
 * 
 * Initialization order is critical for security: sockets requiring CAP_NET_BIND_SERVICE (ports <1024)
 * or CAP_NET_ADMIN (DHCP raw sockets) are created before dropping privileges. On Linux, capabilities
 * are carefully managed: starts with full root, reduces to CAP_NET_ADMIN | CAP_NET_BIND_SERVICE |
 * CAP_NET_RAW after socket creation, then drops CAP_NET_ADMIN unless needed for DHCP, finally drops
 * to minimum required set (CAP_NET_BIND_SERVICE for DNS, CAP_NET_RAW for DHCP ping checks).
 * 
 * The main event loop (lines 1056-1287) implements cooperative multitasking via poll(): sets up file
 * descriptor listeners for all enabled services, calls do_poll() with calculated timeout, then
 * dispatches any ready events to appropriate handlers (check_dns_listeners for DNS, dhcp_packet for
 * DHCP, check_tftp_listeners for TFTP, etc.). Loop continues until EVENT_TERM received via signal pipe.
 * 
 * @param argc Argument count from command line
 * @param argv Argument vector containing command-line options and config file paths
 * @return 0 on clean shutdown, or error code from EC_* constants (see dnsmasq.h) on fatal errors:
 *         EC_BADCONF (1) for configuration errors, EC_BADNET (2) for network setup failures,
 *         EC_FILE (3) for file access errors, EC_NOMEM (4) for memory allocation failures,
 *         EC_INIT (5) for initialization failures, EC_MISC (6) for other errors
 * 
 * @note Drops privileges after socket creation: setuid/setgid to --user option (default "nobody").
 *       On Linux, also manages capabilities via prctl() and capset() to minimize attack surface.
 * @note Forks helper process via create_helper() before dropping root privileges to enable
 *       execution of lease-change scripts and external commands in controlled environment.
 * @note Daemonizes to background unless --no-daemon or --debug options specified, closing stdin/
 *       stdout/stderr and detaching from controlling terminal.
 * @note Signal handlers installed for: SIGHUP (reload config), SIGUSR1 (dump cache stats),
 *       SIGUSR2 (rotate log files), SIGTERM/SIGINT (graceful shutdown with lease file flush),
 *       SIGCHLD (reap TCP child processes), SIGALRM (timer events), SIGPIPE (ignored).
 * 
 * @warning Must be invoked with sufficient privileges to bind privileged ports (<1024) and create
 *          raw sockets for DHCP. Typically requires root or appropriate capabilities on Linux.
 * @warning Never returns under normal operation - runs until killed by signal or fatal error occurs.
 * @warning Modifies global state including daemon pointer, signal handlers, umask, locale settings.
 * 
 * @see read_opts() in option.c for configuration parsing
 * @see create_bound_listeners() in network.c for socket creation
 * @see create_helper() in helper.c for helper process fork
 * @see do_poll() in poll.c for event multiplexing
 * @see docs/ARCHITECTURE.md for detailed initialization sequence and event loop architecture
 * 
 * EXAMPLE USAGE:
 * @code
 * // Typical invocation by init system or manual startup:
 * // ./dnsmasq --conf-file=/etc/dnsmasq.conf --user=dnsmasq --pid-file=/var/run/dnsmasq.pid
 * int main(int argc, char **argv) {
 *     // Called by OS - performs full initialization and never returns
 *     return 0; // Unreachable under normal operation
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements daemon behavior per Unix conventions and LSB. Respects POSIX signal semantics.
 * 
 * SIDE EFFECTS:
 * - Allocates global daemon structure and modifies daemon pointer
 * - Creates network sockets bound to configured addresses/ports
 * - Optionally forks to background (daemonizes) unless --no-daemon specified
 * - Writes PID file to configured location (default /var/run/dnsmasq.pid)
 * - Installs signal handlers for SIGHUP, SIGUSR1, SIGUSR2, SIGTERM, SIGINT, SIGCHLD, SIGALRM
 * - Modifies umask to 022 for predictable file permissions
 * - Drops privileges via setuid/setgid and Linux capability management
 * - Sets locale for internationalization if LOCALEDIR defined
 * - Forks helper process for script execution if HAVE_SCRIPT enabled
 * - Creates self-pipe for async-signal-safe signal delivery to event loop
 * 
 * THREAD SAFETY:
 * Not thread-safe. dnsmasq is strictly single-threaded (though may fork child processes for TCP
 * connections and helper scripts). MUST NOT be called from multiple threads.
 */
int main (int argc, char **argv)
{
  time_t now;
  struct sigaction sigact;
  struct iname *if_tmp;
  int piperead, pipefd[2], err_pipe[2];
  struct passwd *ent_pw = NULL;
#if defined(HAVE_SCRIPT)
  uid_t script_uid = 0;
  gid_t script_gid = 0;
#endif
  struct group *gp = NULL;
  long i, max_fd = sysconf(_SC_OPEN_MAX);
  char *baduser = NULL;
  int log_err;
  int chown_warn = 0;
#if defined(HAVE_LINUX_NETWORK)
  cap_user_header_t hdr = NULL;
  cap_user_data_t data = NULL;
  int need_cap_net_admin = 0;
  int need_cap_net_raw = 0;
  int need_cap_net_bind_service = 0;
  char *bound_device = NULL;
  int did_bind = 0;
  struct server *serv;
  char *netlink_warn;
#else
  int bind_fallback = 0;
#endif 
#if defined(HAVE_DHCP) || defined(HAVE_DHCP6)
  struct dhcp_context *context;
  struct dhcp_relay *relay;
#endif
#ifdef HAVE_TFTP
  int tftp_prefix_missing = 0;
#endif

#if defined(HAVE_IDN) || defined(HAVE_LIBIDN2) || defined(LOCALEDIR)
  setlocale(LC_ALL, "");
#endif
#ifdef LOCALEDIR
  bindtextdomain("dnsmasq", LOCALEDIR); 
  textdomain("dnsmasq");
#endif

  sigact.sa_handler = sig_handler;
  sigact.sa_flags = 0;
  sigemptyset(&sigact.sa_mask);
  sigaction(SIGUSR1, &sigact, NULL);
  sigaction(SIGUSR2, &sigact, NULL);
  sigaction(SIGHUP, &sigact, NULL);
  sigaction(SIGTERM, &sigact, NULL);
  sigaction(SIGALRM, &sigact, NULL);
  sigaction(SIGCHLD, &sigact, NULL);
  sigaction(SIGINT, &sigact, NULL);
  
  /* ignore SIGPIPE */
  sigact.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sigact, NULL);

  umask(022); /* known umask, create leases and pid files as 0644 */

  rand_init(); /* Must precede read_opts() */
  
  read_opts(argc, argv, compile_opts);
 
#ifdef HAVE_LINUX_NETWORK
  daemon->kernel_version = kernel_version();
#endif

  if (daemon->edns_pktsz < PACKETSZ)
    daemon->edns_pktsz = PACKETSZ;

  /* Min buffer size: we check after adding each record, so there must be 
     memory for the largest packet, and the largest record so the
     min for DNS is PACKETSZ+MAXDNAME+RRFIXEDSZ which is < 1000.
     This might be increased is EDNS packet size if greater than the minimum. */ 
  daemon->packet_buff_sz = daemon->edns_pktsz + MAXDNAME + RRFIXEDSZ;
  daemon->packet = safe_malloc(daemon->packet_buff_sz);
  
  if (option_bool(OPT_EXTRALOG))
    daemon->addrbuff2 = safe_malloc(ADDRSTRLEN);
  
#ifdef HAVE_DNSSEC
  if (option_bool(OPT_DNSSEC_VALID))
    {
      /* Note that both /000 and '.' are allowed within labels. These get
	 represented in presentation format using NAME_ESCAPE as an escape
	 character when in DNSSEC mode. 
	 In theory, if all the characters in a name were /000 or
	 '.' or NAME_ESCAPE then all would have to be escaped, so the 
	 presentation format would be twice as long as the spec.

	 daemon->namebuff was previously allocated by the option-reading
	 code before we knew if we're in DNSSEC mode, so reallocate here. */
      free(daemon->namebuff);
      daemon->namebuff = safe_malloc(MAXDNAME * 2);
      daemon->keyname = safe_malloc(MAXDNAME * 2);
      daemon->workspacename = safe_malloc(MAXDNAME * 2);
      /* one char flag per possible RR in answer section (may get extended). */
      daemon->rr_status_sz = 64;
      daemon->rr_status = safe_malloc(sizeof(*daemon->rr_status) * daemon->rr_status_sz);
    }
#endif

#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
  /* CONNTRACK UBUS code uses this buffer, so if not allocated above,
     we need to allocate it here. */
  if (option_bool(OPT_CMARK_ALST_EN) && !daemon->workspacename)
    daemon->workspacename = safe_malloc(MAXDNAME);
#endif
  
#ifdef HAVE_DHCP
  if (!daemon->lease_file)
    {
      if (daemon->dhcp || daemon->dhcp6)
	daemon->lease_file = LEASEFILE;
    }
#endif
  
  /* Ensure that at least stdin, stdout and stderr (fd 0, 1, 2) exist,
     otherwise file descriptors we create can end up being 0, 1, or 2 
     and then get accidentally closed later when we make 0, 1, and 2 
     open to /dev/null. Normally we'll be started with 0, 1 and 2 open, 
     but it's not guaranteed. By opening /dev/null three times, we 
     ensure that we're not using those fds for real stuff. */
  for (i = 0; i < 3; i++)
    open("/dev/null", O_RDWR); 
  
  /* Close any file descriptors we inherited apart from std{in|out|err} */
  close_fds(max_fd, -1, -1, -1);
  
#ifndef HAVE_LINUX_NETWORK
#  if !(defined(IP_RECVDSTADDR) && defined(IP_RECVIF) && defined(IP_SENDSRCADDR))
  if (!option_bool(OPT_NOWILD))
    {
      bind_fallback = 1;
      set_option_bool(OPT_NOWILD);
    }
#  endif
  
  /* -- bind-dynamic not supported on !Linux, fall back to --bind-interfaces */
  if (option_bool(OPT_CLEVERBIND))
    {
      bind_fallback = 1;
      set_option_bool(OPT_NOWILD);
      reset_option_bool(OPT_CLEVERBIND);
    }
#endif

#ifndef HAVE_INOTIFY
  if (daemon->dynamic_dirs)
    die(_("dhcp-hostsdir, dhcp-optsdir and hostsdir are not supported on this platform"), NULL, EC_BADCONF);
#endif
  
  if (option_bool(OPT_DNSSEC_VALID))
    {
#ifdef HAVE_DNSSEC
      struct ds_config *ds;

      /* Must have at least a root trust anchor, or the DNSSEC code
	 can loop forever. */
      for (ds = daemon->ds; ds; ds = ds->next)
	if (ds->name[0] == 0)
	  break;

      if (!ds)
	die(_("no root trust anchor provided for DNSSEC"), NULL, EC_BADCONF);
      
      if (daemon->cachesize < CACHESIZ)
	die(_("cannot reduce cache size from default when DNSSEC enabled"), NULL, EC_BADCONF);
#else 
      die(_("DNSSEC not available: set HAVE_DNSSEC in src/config.h"), NULL, EC_BADCONF);
#endif
    }

#ifndef HAVE_TFTP
  if (option_bool(OPT_TFTP))
    die(_("TFTP server not available: set HAVE_TFTP in src/config.h"), NULL, EC_BADCONF);
#endif

#ifdef HAVE_CONNTRACK
  if (option_bool(OPT_CONNTRACK))
    {
      if (daemon->query_port != 0 || daemon->osport)
	die (_("cannot use --conntrack AND --query-port"), NULL, EC_BADCONF);

      need_cap_net_admin = 1;
    }
#else
  if (option_bool(OPT_CONNTRACK))
    die(_("conntrack support not available: set HAVE_CONNTRACK in src/config.h"), NULL, EC_BADCONF);
#endif

#ifdef HAVE_SOLARIS_NETWORK
  if (daemon->max_logs != 0)
    die(_("asynchronous logging is not available under Solaris"), NULL, EC_BADCONF);
#endif
  
#ifdef __ANDROID__
  if (daemon->max_logs != 0)
    die(_("asynchronous logging is not available under Android"), NULL, EC_BADCONF);
#endif

#ifndef HAVE_AUTH
  if (daemon->auth_zones)
    die(_("authoritative DNS not available: set HAVE_AUTH in src/config.h"), NULL, EC_BADCONF);
#endif

#ifndef HAVE_LOOP
  if (option_bool(OPT_LOOP_DETECT))
    die(_("loop detection not available: set HAVE_LOOP in src/config.h"), NULL, EC_BADCONF);
#endif

#ifndef HAVE_UBUS
  if (option_bool(OPT_UBUS))
    die(_("Ubus not available: set HAVE_UBUS in src/config.h"), NULL, EC_BADCONF);
#endif
  
  /* Handle only one of min_port/max_port being set. */
  if (daemon->min_port != 0 && daemon->max_port == 0)
    daemon->max_port = MAX_PORT;
  
  if (daemon->max_port != 0 && daemon->min_port == 0)
    daemon->min_port = MIN_PORT;
   
  if (daemon->max_port < daemon->min_port)
    die(_("max_port cannot be smaller than min_port"), NULL, EC_BADCONF);
  
  now = dnsmasq_time();

  if (daemon->auth_zones)
    {
      if (!daemon->authserver)
	die(_("--auth-server required when an auth zone is defined."), NULL, EC_BADCONF);

      /* Create a serial at startup if not configured. */
#ifdef HAVE_BROKEN_RTC
      if (daemon->soa_sn == 0)
	die(_("zone serial must be configured in --auth-soa"), NULL, EC_BADCONF);
#else
      if (daemon->soa_sn == 0)
	daemon->soa_sn = now;
#endif
    }
  
#ifdef HAVE_DHCP6
  if (daemon->dhcp6)
    {
      daemon->doing_ra = option_bool(OPT_RA);
      
      for (context = daemon->dhcp6; context; context = context->next)
	{
	  if (context->flags & CONTEXT_DHCP)
	    daemon->doing_dhcp6 = 1;
	  if (context->flags & CONTEXT_RA)
	    daemon->doing_ra = 1;
#if !defined(HAVE_LINUX_NETWORK) && !defined(HAVE_BSD_NETWORK)
	  if (context->flags & CONTEXT_TEMPLATE)
	    die (_("dhcp-range constructor not available on this platform"), NULL, EC_BADCONF);
#endif 
	}
    }
#endif
  
#ifdef HAVE_DHCP
  /* Note that order matters here, we must call lease_init before
     creating any file descriptors which shouldn't be leaked
     to the lease-script init process. We need to call common_init
     before lease_init to allocate buffers it uses.
     The script subsystem relies on DHCP buffers, hence the last two
     conditions below. */  
  if (daemon->dhcp || daemon->doing_dhcp6 || daemon->relay4 || 
      daemon->relay6 || option_bool(OPT_TFTP) || option_bool(OPT_SCRIPT_ARP))
    {
      dhcp_common_init();
      if (daemon->dhcp || daemon->doing_dhcp6)
	lease_init(now);
    }
  
  if (daemon->dhcp || daemon->relay4)
    {
      dhcp_init();
#   ifdef HAVE_LINUX_NETWORK
      if (!option_bool(OPT_NO_PING))
	need_cap_net_raw = 1;
      need_cap_net_admin = 1;
#   endif
    }
  
#  ifdef HAVE_DHCP6
  if (daemon->doing_ra || daemon->doing_dhcp6 || daemon->relay6)
    {
      ra_init(now);
#   ifdef HAVE_LINUX_NETWORK
      need_cap_net_raw = 1;
      need_cap_net_admin = 1;
#   endif
    }
  
  if (daemon->doing_dhcp6 || daemon->relay6)
    dhcp6_init();
#  endif

#endif

#ifdef HAVE_IPSET
  if (daemon->ipsets)
    {
      ipset_init();
#  ifdef HAVE_LINUX_NETWORK
      need_cap_net_admin = 1;
#  endif
    }
#endif

#ifdef HAVE_NFTSET
  if (daemon->nftsets)
    {
      nftset_init();
#  ifdef HAVE_LINUX_NETWORK
      need_cap_net_admin = 1;
#  endif
    }
#endif

#if  defined(HAVE_LINUX_NETWORK)
  netlink_warn = netlink_init();
#elif defined(HAVE_BSD_NETWORK)
  route_init();
#endif

  if (option_bool(OPT_NOWILD) && option_bool(OPT_CLEVERBIND))
    die(_("cannot set --bind-interfaces and --bind-dynamic"), NULL, EC_BADCONF);
  
  if (!enumerate_interfaces(1) || !enumerate_interfaces(0))
    die(_("failed to find list of interfaces: %s"), NULL, EC_MISC);
  
  if (option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND)) 
    {
      create_bound_listeners(1);
      
      if (!option_bool(OPT_CLEVERBIND))
	for (if_tmp = daemon->if_names; if_tmp; if_tmp = if_tmp->next)
	  if (if_tmp->name && !if_tmp->used)
	    die(_("unknown interface %s"), if_tmp->name, EC_BADNET);

#if defined(HAVE_LINUX_NETWORK) && defined(HAVE_DHCP)
      /* after enumerate_interfaces()  */
      bound_device = whichdevice();

      if ((did_bind = bind_dhcp_devices(bound_device)) & 2)
	die(_("failed to set SO_BINDTODEVICE on DHCP socket: %s"), NULL, EC_BADNET);	
#endif
    }
  else 
    create_wildcard_listeners();
 
#ifdef HAVE_DHCP6
  /* after enumerate_interfaces() */
  if (daemon->doing_dhcp6 || daemon->relay6 || daemon->doing_ra)
    join_multicast(1);

  /* After netlink_init() and before create_helper() */
  lease_make_duid(now);
#endif
  
  if (daemon->port != 0)
    {
      cache_init();
      blockdata_init();
      hash_questions_init();

      /* Scale random socket pool by ftabsize, but
	 limit it based on available fds. */
      daemon->numrrand = daemon->ftabsize/2;
      if (daemon->numrrand > max_fd/3)
	daemon->numrrand = max_fd/3;
      /* safe_malloc returns zero'd memory */
      daemon->randomsocks = safe_malloc(daemon->numrrand * sizeof(struct randfd));
    }

#ifdef HAVE_INOTIFY
  if ((daemon->port != 0 || daemon->dhcp || daemon->doing_dhcp6)
      && (!option_bool(OPT_NO_RESOLV) || daemon->dynamic_dirs))
    inotify_dnsmasq_init();
  else
    daemon->inotifyfd = -1;
#endif

  if (daemon->dump_file)
#ifdef HAVE_DUMPFILE
    dump_init();
  else 
    daemon->dumpfd = -1;
#else
  die(_("Packet dumps not available: set HAVE_DUMP in src/config.h"), NULL, EC_BADCONF);
#endif
  
  if (option_bool(OPT_DBUS))
#ifdef HAVE_DBUS
    {
      char *err;
      if ((err = dbus_init()))
	die(_("DBus error: %s"), err, EC_MISC);
    }
#else
  die(_("DBus not available: set HAVE_DBUS in src/config.h"), NULL, EC_BADCONF);
#endif

  if (option_bool(OPT_UBUS))
#ifdef HAVE_UBUS
    {
      char *err;
      if ((err = ubus_init()))
	die(_("UBus error: %s"), err, EC_MISC);
    }
#else
  die(_("UBus not available: set HAVE_UBUS in src/config.h"), NULL, EC_BADCONF);
#endif

  if (daemon->port != 0)
    pre_allocate_sfds();

#if defined(HAVE_SCRIPT)
  /* Note getpwnam returns static storage */
  if ((daemon->dhcp || daemon->dhcp6) && 
      daemon->scriptuser && 
      (daemon->lease_change_command || daemon->luascript))
    {
      struct passwd *scr_pw;
      
      if ((scr_pw = getpwnam(daemon->scriptuser)))
	{
	  script_uid = scr_pw->pw_uid;
	  script_gid = scr_pw->pw_gid;
	 }
      else
	baduser = daemon->scriptuser;
    }
#endif
  
  if (daemon->username && !(ent_pw = getpwnam(daemon->username)))
    baduser = daemon->username;
  else if (daemon->groupname && !(gp = getgrnam(daemon->groupname)))
    baduser = daemon->groupname;

  if (baduser)
    die(_("unknown user or group: %s"), baduser, EC_BADCONF);

  /* implement group defaults, "dip" if available, or group associated with uid */
  if (!daemon->group_set && !gp)
    {
      if (!(gp = getgrnam(CHGRP)) && ent_pw)
	gp = getgrgid(ent_pw->pw_gid);
      
      /* for error message */
      if (gp)
	daemon->groupname = gp->gr_name; 
    }

#if defined(HAVE_LINUX_NETWORK)
  /* We keep CAP_NETADMIN (for ARP-injection) and
     CAP_NET_RAW (for icmp) if we're doing dhcp,
     if we have yet to bind ports because of DAD, 
     or we're doing it dynamically, we need CAP_NET_BIND_SERVICE. */
  if ((is_dad_listeners() || option_bool(OPT_CLEVERBIND)) &&
      (option_bool(OPT_TFTP) || (daemon->port != 0 && daemon->port <= 1024)))
    need_cap_net_bind_service = 1;

  /* usptream servers which bind to an interface call SO_BINDTODEVICE
     for each TCP connection, so need CAP_NET_RAW */
  for (serv = daemon->servers; serv; serv = serv->next)
    if (serv->interface[0] != 0)
      need_cap_net_raw = 1;

  /* If we're doing Dbus or UBus, the above can be set dynamically,
     (as can ports) so always (potentially) needed. */
#ifdef HAVE_DBUS
  if (option_bool(OPT_DBUS))
    {
      need_cap_net_bind_service = 1;
      need_cap_net_raw = 1;
    }
#endif

#ifdef HAVE_UBUS
  if (option_bool(OPT_UBUS))
    {
      need_cap_net_bind_service = 1;
      need_cap_net_raw = 1;
    }
#endif
  
  /* determine capability API version here, while we can still
     call safe_malloc */
  int capsize = 1; /* for header version 1 */
  char *fail = NULL;
  
  hdr = safe_malloc(sizeof(*hdr));
  
  /* find version supported by kernel */
  memset(hdr, 0, sizeof(*hdr));
  capget(hdr, NULL);
  
  if (hdr->version != LINUX_CAPABILITY_VERSION_1)
    {
      /* if unknown version, use largest supported version (3) */
      if (hdr->version != LINUX_CAPABILITY_VERSION_2)
	hdr->version = LINUX_CAPABILITY_VERSION_3;
      capsize = 2;
    }
  
  data = safe_malloc(sizeof(*data) * capsize);
  capget(hdr, data); /* Get current values, for verification */

  if (need_cap_net_admin && !(data->permitted & (1 << CAP_NET_ADMIN)))
    fail = "NET_ADMIN";
  else if (need_cap_net_raw && !(data->permitted & (1 << CAP_NET_RAW)))
    fail = "NET_RAW";
  else if (need_cap_net_bind_service && !(data->permitted & (1 << CAP_NET_BIND_SERVICE)))
    fail = "NET_BIND_SERVICE";
  
  if (fail)
    die(_("process is missing required capability %s"), fail, EC_MISC);

  /* Now set bitmaps to set caps after daemonising */
  memset(data, 0, sizeof(*data) * capsize);
  
  if (need_cap_net_admin)
    data->effective |= (1 << CAP_NET_ADMIN);
  if (need_cap_net_raw)
    data->effective |= (1 << CAP_NET_RAW);
  if (need_cap_net_bind_service)
    data->effective |= (1 << CAP_NET_BIND_SERVICE);
  
  data->permitted = data->effective;  
#endif

  /* Use a pipe to carry signals and other events back to the event loop 
     in a race-free manner and another to carry errors to daemon-invoking process */
  safe_pipe(pipefd, 1);
  
  piperead = pipefd[0];
  pipewrite = pipefd[1];
  /* prime the pipe to load stuff first time. */
  send_event(pipewrite, EVENT_INIT, 0, NULL); 

  err_pipe[1] = -1;
  
  if (!option_bool(OPT_DEBUG))   
    {
      /* The following code "daemonizes" the process. 
	 See Stevens section 12.4 */
      
      if (chdir("/") != 0)
	die(_("cannot chdir to filesystem root: %s"), NULL, EC_MISC); 

      if (!option_bool(OPT_NO_FORK))
	{
	  pid_t pid;
	  
	  /* pipe to carry errors back to original process.
	     When startup is complete we close this and the process terminates. */
	  safe_pipe(err_pipe, 0);
	  
	  if ((pid = fork()) == -1)
	    /* fd == -1 since we've not forked, never returns. */
	    send_event(-1, EVENT_FORK_ERR, errno, NULL);
	   
	  if (pid != 0)
	    {
	      struct event_desc ev;
	      char *msg;

	      /* close our copy of write-end */
	      close(err_pipe[1]);
	      
	      /* check for errors after the fork */
	      if (read_event(err_pipe[0], &ev, &msg))
		fatal_event(&ev, msg);
	      
	      _exit(EC_GOOD);
	    } 
	  
	  close(err_pipe[0]);

	  /* NO calls to die() from here on. */
	  
	  setsid();
	 
	  if ((pid = fork()) == -1)
	    send_event(err_pipe[1], EVENT_FORK_ERR, errno, NULL);
	 
	  if (pid != 0)
	    _exit(0);
	}
            
      /* write pidfile _after_ forking ! */
      if (daemon->runfile)
	{
	  int fd, err = 0;

	  sprintf(daemon->namebuff, "%d\n", (int) getpid());

	  /* Explanation: Some installations of dnsmasq (eg Debian/Ubuntu) locate the pid-file
	     in a directory which is writable by the non-privileged user that dnsmasq runs as. This
	     allows the daemon to delete the file as part of its shutdown. This is a security hole to the 
	     extent that an attacker running as the unprivileged  user could replace the pidfile with a 
	     symlink, and have the target of that symlink overwritten as root next time dnsmasq starts. 

	     The following code first deletes any existing file, and then opens it with the O_EXCL flag,
	     ensuring that the open() fails should there be any existing file (because the unlink() failed, 
	     or an attacker exploited the race between unlink() and open()). This ensures that no symlink
	     attack can succeed. 

	     Any compromise of the non-privileged user still theoretically allows the pid-file to be
	     replaced whilst dnsmasq is running. The worst that could allow is that the usual 
	     "shutdown dnsmasq" shell command could be tricked into stopping any other process.

	     Note that if dnsmasq is started as non-root (eg for testing) it silently ignores 
	     failure to write the pid-file.
	  */

	  unlink(daemon->runfile); 
	  
	  if ((fd = open(daemon->runfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH)) == -1)
	    {
	      /* only complain if started as root */
	      if (getuid() == 0)
		err = 1;
	    }
	  else
	    {
	      /* We're still running as root here. Change the ownership of the PID file
		 to the user we will be running as. Note that this is not to allow
		 us to delete the file, since that depends on the permissions 
		 of the directory containing the file. That directory will
		 need to by owned by the dnsmasq user, and the ownership of the
		 file has to match, to keep systemd >273 happy. */
	      if (getuid() == 0 && ent_pw && ent_pw->pw_uid != 0 && fchown(fd, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
		chown_warn = errno;

	      if (!read_write(fd, (unsigned char *)daemon->namebuff, strlen(daemon->namebuff), 0))
		err = 1;
	      else
		{
		  if (close(fd) == -1)
		    err = 1;
		}
	    }

	  if (err)
	    {
	      send_event(err_pipe[1], EVENT_PIDFILE, errno, daemon->runfile);
	      _exit(0);
	    }
	}
    }
  
   log_err = log_start(ent_pw, err_pipe[1]);

   if (!option_bool(OPT_DEBUG)) 
     {       
       /* open  stdout etc to /dev/null */
       int nullfd = open("/dev/null", O_RDWR);
       if (nullfd != -1)
	 {
	   dup2(nullfd, STDOUT_FILENO);
	   dup2(nullfd, STDERR_FILENO);
	   dup2(nullfd, STDIN_FILENO);
	   close(nullfd);
	 }
     }
   
   /* if we are to run scripts, we need to fork a helper before dropping root. */
  daemon->helperfd = -1;
#ifdef HAVE_SCRIPT 
  if ((daemon->dhcp ||
       daemon->dhcp6 ||
       daemon->relay6 ||
       option_bool(OPT_TFTP) ||
       option_bool(OPT_SCRIPT_ARP)) && 
      (daemon->lease_change_command || daemon->luascript))
      daemon->helperfd = create_helper(pipewrite, err_pipe[1], script_uid, script_gid, max_fd);
#endif

  if (!option_bool(OPT_DEBUG) && getuid() == 0)   
    {
      int bad_capabilities = 0;
      gid_t dummy;
      
      /* remove all supplementary groups */
      if (gp && 
	  (setgroups(0, &dummy) == -1 ||
	   setgid(gp->gr_gid) == -1))
	{
	  send_event(err_pipe[1], EVENT_GROUP_ERR, errno, daemon->groupname);
	  _exit(0);
	}
  
      if (ent_pw && ent_pw->pw_uid != 0)
	{     
#if defined(HAVE_LINUX_NETWORK)	  
	  /* Need to be able to drop root. */
	  data->effective |= (1 << CAP_SETUID);
	  data->permitted |= (1 << CAP_SETUID);
	  /* Tell kernel to not clear capabilities when dropping root */
	  if (capset(hdr, data) == -1 || prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1)
	    bad_capabilities = errno;
			  
#elif defined(HAVE_SOLARIS_NETWORK)
	  /* http://developers.sun.com/solaris/articles/program_privileges.html */
	  priv_set_t *priv_set;
	  
	  if (!(priv_set = priv_str_to_set("basic", ",", NULL)) ||
	      priv_addset(priv_set, PRIV_NET_ICMPACCESS) == -1 ||
	      priv_addset(priv_set, PRIV_SYS_NET_CONFIG) == -1)
	    bad_capabilities = errno;

	  if (priv_set && bad_capabilities == 0)
	    {
	      priv_inverse(priv_set);
	  
	      if (setppriv(PRIV_OFF, PRIV_LIMIT, priv_set) == -1)
		bad_capabilities = errno;
	    }

	  if (priv_set)
	    priv_freeset(priv_set);

#endif    

	  if (bad_capabilities != 0)
	    {
	      send_event(err_pipe[1], EVENT_CAP_ERR, bad_capabilities, NULL);
	      _exit(0);
	    }
	  
	  /* finally drop root */
	  if (setuid(ent_pw->pw_uid) == -1)
	    {
	      send_event(err_pipe[1], EVENT_USER_ERR, errno, daemon->username);
	      _exit(0);
	    }     

#ifdef HAVE_LINUX_NETWORK
	  data->effective &= ~(1 << CAP_SETUID);
	  data->permitted &= ~(1 << CAP_SETUID);
	  
	  /* lose the setuid capability */
	  if (capset(hdr, data) == -1)
	    {
	      send_event(err_pipe[1], EVENT_CAP_ERR, errno, NULL);
	      _exit(0);
	    }
#endif
	  
	}
    }
  
#ifdef HAVE_LINUX_NETWORK
  free(hdr);
  free(data);
  if (option_bool(OPT_DEBUG)) 
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
#endif

#ifdef HAVE_TFTP
  if (option_bool(OPT_TFTP))
    {
      DIR *dir;
      struct tftp_prefix *p;
      
      if (daemon->tftp_prefix)
	{
	  if (!((dir = opendir(daemon->tftp_prefix))))
	    {
	      tftp_prefix_missing = 1;
	      if (!option_bool(OPT_TFTP_NO_FAIL))
	        {
	          send_event(err_pipe[1], EVENT_TFTP_ERR, errno, daemon->tftp_prefix);
	          _exit(0);
	        }
	    }
	  else
	    closedir(dir);
	}

      for (p = daemon->if_prefix; p; p = p->next)
	{
	  p->missing = 0;
	  if (!((dir = opendir(p->prefix))))
	    {
	      p->missing = 1;
	      if (!option_bool(OPT_TFTP_NO_FAIL))
		{
		  send_event(err_pipe[1], EVENT_TFTP_ERR, errno, p->prefix);
		  _exit(0);
		}
	    }
	  else
	    closedir(dir);
	}
    }
#endif

  if (daemon->port == 0)
    my_syslog(LOG_INFO, _("started, version %s DNS disabled"), VERSION);
  else 
    {
      if (daemon->cachesize != 0)
	{
	  my_syslog(LOG_INFO, _("started, version %s cachesize %d"), VERSION, daemon->cachesize);
	  if (daemon->cachesize > 10000)
	    my_syslog(LOG_WARNING, _("cache size greater than 10000 may cause performance issues, and is unlikely to be useful."));
	}
      else
	my_syslog(LOG_INFO, _("started, version %s cache disabled"), VERSION);

      if (option_bool(OPT_LOCAL_SERVICE))
	my_syslog(LOG_INFO, _("DNS service limited to local subnets"));
    }
  
  my_syslog(LOG_INFO, _("compile time options: %s"), compile_opts);

  if (chown_warn != 0)
    my_syslog(LOG_WARNING, "chown of PID file %s failed: %s", daemon->runfile, strerror(chown_warn));
  
#ifdef HAVE_DBUS
  if (option_bool(OPT_DBUS))
    {
      if (daemon->dbus)
	my_syslog(LOG_INFO, _("DBus support enabled: connected to system bus"));
      else
	my_syslog(LOG_INFO, _("DBus support enabled: bus connection pending"));
    }
#endif

#ifdef HAVE_UBUS
  if (option_bool(OPT_UBUS))
    {
      if (daemon->ubus)
        my_syslog(LOG_INFO, _("UBus support enabled: connected to system bus"));
      else
        my_syslog(LOG_INFO, _("UBus support enabled: bus connection pending"));
    }
#endif

#ifdef HAVE_DNSSEC
  if (option_bool(OPT_DNSSEC_VALID))
    {
      int rc;
      struct ds_config *ds;
      
      /* Delay creating the timestamp file until here, after we've changed user, so that
	 it has the correct owner to allow updating the mtime later. 
	 This means we have to report fatal errors via the pipe. */
      if ((rc = setup_timestamp()) == -1)
	{
	  send_event(err_pipe[1], EVENT_TIME_ERR, errno, daemon->timestamp_file);
	  _exit(0);
	}
      
      if (option_bool(OPT_DNSSEC_IGN_NS))
	my_syslog(LOG_INFO, _("DNSSEC validation enabled but all unsigned answers are trusted"));
      else
	my_syslog(LOG_INFO, _("DNSSEC validation enabled"));
      
      daemon->dnssec_no_time_check = option_bool(OPT_DNSSEC_TIME);
      if (option_bool(OPT_DNSSEC_TIME) && !daemon->back_to_the_future)
	my_syslog(LOG_INFO, _("DNSSEC signature timestamps not checked until receipt of SIGINT"));
      
      if (rc == 1)
	my_syslog(LOG_INFO, _("DNSSEC signature timestamps not checked until system time valid"));

      for (ds = daemon->ds; ds; ds = ds->next)
	my_syslog(LOG_INFO, _("configured with trust anchor for %s keytag %u"),
		  ds->name[0] == 0 ? "<root>" : ds->name, ds->keytag);
    }
#endif

  if (log_err != 0)
    my_syslog(LOG_WARNING, _("warning: failed to change owner of %s: %s"), 
	      daemon->log_file, strerror(log_err));
  
#ifndef HAVE_LINUX_NETWORK
  if (bind_fallback)
    my_syslog(LOG_WARNING, _("setting --bind-interfaces option because of OS limitations"));
#endif

  if (option_bool(OPT_NOWILD))
    warn_bound_listeners();
  else if (!option_bool(OPT_CLEVERBIND))
    warn_wild_labels();

  warn_int_names();
  
  if (!option_bool(OPT_NOWILD)) 
    for (if_tmp = daemon->if_names; if_tmp; if_tmp = if_tmp->next)
      if (if_tmp->name && !if_tmp->used)
	my_syslog(LOG_WARNING, _("warning: interface %s does not currently exist"), if_tmp->name);
   
  if (daemon->port != 0 && option_bool(OPT_NO_RESOLV))
    {
      if (daemon->resolv_files && !daemon->resolv_files->is_default)
	my_syslog(LOG_WARNING, _("warning: ignoring resolv-file flag because no-resolv is set"));
      daemon->resolv_files = NULL;
      if (!daemon->servers)
	my_syslog(LOG_WARNING, _("warning: no upstream servers configured"));
    } 

  if (daemon->max_logs != 0)
    my_syslog(LOG_INFO, _("asynchronous logging enabled, queue limit is %d messages"), daemon->max_logs);
  

#ifdef HAVE_DHCP
  for (context = daemon->dhcp; context; context = context->next)
    log_context(AF_INET, context);

  for (relay = daemon->relay4; relay; relay = relay->next)
    log_relay(AF_INET, relay);

#  ifdef HAVE_DHCP6
  for (context = daemon->dhcp6; context; context = context->next)
    log_context(AF_INET6, context);

  for (relay = daemon->relay6; relay; relay = relay->next)
    log_relay(AF_INET6, relay);
  
  if (daemon->doing_dhcp6 || daemon->doing_ra)
    dhcp_construct_contexts(now);
  
  if (option_bool(OPT_RA))
    my_syslog(MS_DHCP | LOG_INFO, _("IPv6 router advertisement enabled"));
#  endif

#  ifdef HAVE_LINUX_NETWORK
  if (did_bind)
    my_syslog(MS_DHCP | LOG_INFO, _("DHCP, sockets bound exclusively to interface %s"), bound_device);

  if (netlink_warn)
    my_syslog(LOG_WARNING, netlink_warn);
#  endif

  /* after dhcp_construct_contexts */
  if (daemon->dhcp || daemon->doing_dhcp6)
    lease_find_interfaces(now);
#endif

#ifdef HAVE_TFTP
  if (option_bool(OPT_TFTP))
    {
      struct tftp_prefix *p;

      my_syslog(MS_TFTP | LOG_INFO, "TFTP %s%s %s %s", 
		daemon->tftp_prefix ? _("root is ") : _("enabled"),
		daemon->tftp_prefix ? daemon->tftp_prefix : "",
		option_bool(OPT_TFTP_SECURE) ? _("secure mode") : "",
		option_bool(OPT_SINGLE_PORT) ? _("single port mode") : "");

      if (tftp_prefix_missing)
	my_syslog(MS_TFTP | LOG_WARNING, _("warning: %s inaccessible"), daemon->tftp_prefix);

      for (p = daemon->if_prefix; p; p = p->next)
	if (p->missing)
	   my_syslog(MS_TFTP | LOG_WARNING, _("warning: TFTP directory %s inaccessible"), p->prefix);

      /* This is a guess, it assumes that for small limits, 
	 disjoint files might be served, but for large limits, 
	 a single file will be sent to may clients (the file only needs
	 one fd). */

      max_fd -= 30 + daemon->numrrand; /* use other than TFTP */
      
      if (max_fd < 0)
	max_fd = 5;
      else if (max_fd < 100 && !option_bool(OPT_SINGLE_PORT))
	max_fd = max_fd/2;
      else
	max_fd = max_fd - 20;
      
      /* if we have to use a limited range of ports, 
	 that will limit the number of transfers */
      if (daemon->start_tftp_port != 0 &&
	  daemon->end_tftp_port - daemon->start_tftp_port + 1 < max_fd)
	max_fd = daemon->end_tftp_port - daemon->start_tftp_port + 1;

      if (daemon->tftp_max > max_fd)
	{
	  daemon->tftp_max = max_fd;
	  my_syslog(MS_TFTP | LOG_WARNING, 
		    _("restricting maximum simultaneous TFTP transfers to %d"), 
		    daemon->tftp_max);
	}
    }
#endif

  /* finished start-up - release original process */
  if (err_pipe[1] != -1)
    close(err_pipe[1]);
  
  if (daemon->port != 0)
    check_servers(0);
  
  pid = getpid();

  daemon->pipe_to_parent = -1;
  for (i = 0; i < MAX_PROCS; i++)
    daemon->tcp_pipes[i] = -1;
  
#ifdef HAVE_INOTIFY
  /* Using inotify, have to select a resolv file at startup */
  poll_resolv(1, 0, now);
#endif
  
  while (1)
    {
      int timeout = -1;
      
      poll_reset();
      
      /* Whilst polling for the dbus, or doing a tftp transfer, wake every quarter second */
      if (daemon->tftp_trans ||
	  (option_bool(OPT_DBUS) && !daemon->dbus))
	timeout = 250;

      /* Wake every second whilst waiting for DAD to complete */
      else if (is_dad_listeners())
	timeout = 1000;

      set_dns_listeners();

#ifdef HAVE_DBUS
      if (option_bool(OPT_DBUS))
	set_dbus_listeners();
#endif
      
#ifdef HAVE_UBUS
      if (option_bool(OPT_UBUS))
        set_ubus_listeners();
#endif
      
#ifdef HAVE_DHCP
#  if defined(HAVE_LINUX_NETWORK)
      if (bind_dhcp_devices(bound_device) & 2)
	{
	  static int warned = 0;
	  if (!warned)
	    {
	      my_syslog(LOG_ERR, _("error binding DHCP socket to device %s"), bound_device);
	      warned = 1;
	    }
	}
# endif
      if (daemon->dhcp || daemon->relay4)
	{
	  poll_listen(daemon->dhcpfd, POLLIN);
	  if (daemon->pxefd != -1)
	    poll_listen(daemon->pxefd, POLLIN);
	}
#endif

#ifdef HAVE_DHCP6
      if (daemon->doing_dhcp6 || daemon->relay6)
	poll_listen(daemon->dhcp6fd, POLLIN);
	
      if (daemon->doing_ra)
	poll_listen(daemon->icmp6fd, POLLIN); 
#endif
    
#ifdef HAVE_INOTIFY
      if (daemon->inotifyfd != -1)
	poll_listen(daemon->inotifyfd, POLLIN);
#endif

#if defined(HAVE_LINUX_NETWORK)
      poll_listen(daemon->netlinkfd, POLLIN);
#elif defined(HAVE_BSD_NETWORK)
      poll_listen(daemon->routefd, POLLIN);
#endif
      
      poll_listen(piperead, POLLIN);

#ifdef HAVE_SCRIPT
#    ifdef HAVE_DHCP
      while (helper_buf_empty() && do_script_run(now)); 
#    endif

      /* Refresh cache */
      if (option_bool(OPT_SCRIPT_ARP))
	find_mac(NULL, NULL, 0, now);
      while (helper_buf_empty() && do_arp_script_run());

#    ifdef HAVE_TFTP
      while (helper_buf_empty() && do_tftp_script_run());
#    endif

#    ifdef HAVE_DHCP6
      while (helper_buf_empty() && do_snoop_script_run());
#    endif
      
      if (!helper_buf_empty())
	poll_listen(daemon->helperfd, POLLOUT);
#else
      /* need this for other side-effects */
#    ifdef HAVE_DHCP
      while (do_script_run(now));
#    endif

      while (do_arp_script_run());

#    ifdef HAVE_TFTP 
      while (do_tftp_script_run());
#    endif

#endif

   
      /* must do this just before do_poll(), when we know no
	 more calls to my_syslog() can occur */
      set_log_writer();
      
      if (do_poll(timeout) < 0)
	continue;
      
      now = dnsmasq_time();

      check_log_writer(0);

      /* prime. */
      enumerate_interfaces(1);

      /* Check the interfaces to see if any have exited DAD state
	 and if so, bind the address. */
      if (is_dad_listeners())
	{
	  enumerate_interfaces(0);
	  /* NB, is_dad_listeners() == 1 --> we're binding interfaces */
	  create_bound_listeners(0);
	  warn_bound_listeners();
	}

#if defined(HAVE_LINUX_NETWORK)
      if (poll_check(daemon->netlinkfd, POLLIN))
	netlink_multicast();
#elif defined(HAVE_BSD_NETWORK)
      if (poll_check(daemon->routefd, POLLIN))
	route_sock();
#endif

#ifdef HAVE_INOTIFY
      if  (daemon->inotifyfd != -1 && poll_check(daemon->inotifyfd, POLLIN) && inotify_check(now))
	{
	  if (daemon->port != 0 && !option_bool(OPT_NO_POLL))
	    poll_resolv(1, 1, now);
	} 	  
#else
      /* Check for changes to resolv files once per second max. */
      /* Don't go silent for long periods if the clock goes backwards. */
      if (daemon->last_resolv == 0 || 
	  difftime(now, daemon->last_resolv) > 1.0 || 
	  difftime(now, daemon->last_resolv) < -1.0)
	{
	  /* poll_resolv doesn't need to reload first time through, since 
	     that's queued anyway. */

	  poll_resolv(0, daemon->last_resolv != 0, now); 	  
	  daemon->last_resolv = now;
	}
#endif

      if (poll_check(piperead, POLLIN))
	async_event(piperead, now);
      
#ifdef HAVE_DBUS
      /* if we didn't create a DBus connection, retry now. */ 
      if (option_bool(OPT_DBUS))
	{
	  if (!daemon->dbus)
	    {
	      char *err  = dbus_init();

	      if (daemon->dbus)
		my_syslog(LOG_INFO, _("connected to system DBus"));
	      else if (err)
		{
		  my_syslog(LOG_ERR, _("DBus error: %s"), err);
		  reset_option_bool(OPT_DBUS); /* fatal error, stop trying. */
		}
	    }
	  
	  check_dbus_listeners();
	}
#endif

#ifdef HAVE_UBUS
      /* if we didn't create a UBus connection, retry now. */
      if (option_bool(OPT_UBUS))
	{
	  if (!daemon->ubus)
	    {
	      char *err = ubus_init();

	      if (daemon->ubus)
		my_syslog(LOG_INFO, _("connected to system UBus"));
	      else if (err)
		{
		  my_syslog(LOG_ERR, _("UBus error: %s"), err);
		  reset_option_bool(OPT_UBUS); /* fatal error, stop trying. */
		}
	    }
	  
	  check_ubus_listeners();
	}
#endif

      check_dns_listeners(now);

#ifdef HAVE_TFTP
      check_tftp_listeners(now);
#endif      

#ifdef HAVE_DHCP
      if (daemon->dhcp || daemon->relay4)
	{
	  if (poll_check(daemon->dhcpfd, POLLIN))
	    dhcp_packet(now, 0);
	  if (daemon->pxefd != -1 && poll_check(daemon->pxefd, POLLIN))
	    dhcp_packet(now, 1);
	}

#ifdef HAVE_DHCP6
      if ((daemon->doing_dhcp6 || daemon->relay6) && poll_check(daemon->dhcp6fd, POLLIN))
	dhcp6_packet(now);

      if (daemon->doing_ra && poll_check(daemon->icmp6fd, POLLIN))
	icmp6_packet(now);
#endif

#  ifdef HAVE_SCRIPT
      if (daemon->helperfd != -1 && poll_check(daemon->helperfd, POLLOUT))
	helper_write();
#  endif
#endif

    }
}

/**
 * @brief POSIX signal handler using self-pipe pattern for async-signal-safe event delivery
 * 
 * @detailed
 * Async-signal-safe signal handler invoked when POSIX signals (SIGHUP, SIGTERM, SIGINT, SIGUSR1, SIGUSR2,
 * SIGCHLD, SIGALRM) are delivered to dnsmasq process. Implements self-pipe pattern to safely defer signal
 * processing to main event loop: translates signal number to internal event code, calls send_event() to
 * write event descriptor to non-blocking pipe, then returns immediately. Main loop's async_event() reads
 * pipe and processes events in non-signal context where full API is available.
 * 
 * Handles three cases based on global pid variable state:
 * 1. pid == 0: Startup or helper process - ignore all signals except TERM/INT which exit immediately
 * 2. pid != getpid(): TCP child process - only handles SIGALRM for connection timeout (exits)
 * 3. pid == getpid(): Master process - translates all signals to events and queues via self-pipe
 * 
 * Signal to event mapping: SIGHUP→EVENT_RELOAD (reload config), SIGCHLD→EVENT_CHILD (reap children),
 * SIGALRM→EVENT_ALARM (timer expiry), SIGTERM→EVENT_TERM (graceful shutdown), SIGUSR1→EVENT_DUMP
 * (cache dump), SIGUSR2→EVENT_REOPEN (log rotation), SIGINT→EVENT_TIME (DNSSEC time check) unless
 * debug mode then exits.
 * 
 * @param sig Signal number from POSIX signal delivery (SIGHUP=1, SIGINT=2, SIGTERM=15, SIGCHLD=17,
 *            SIGALRM=14, SIGUSR1=10, SIGUSR2=12)
 * 
 * @note Only uses async-signal-safe functions: send_event() with NULL msg, errno save/restore
 * @note Preserves and restores errno to avoid interfering with interrupted system calls
 * @note Returns immediately after queueing event - actual processing deferred to async_event()
 * @note Installed via sigaction() in main() with SA_RESTART for automatic syscall restart
 * 
 * @warning MUST NOT call non-async-signal-safe functions (malloc, printf, most library functions)
 * @warning Only send_event() with NULL message is async-signal-safe (no malloc in msg path)
 * @warning Race condition possible if signal delivered during critical section - use self-pipe to defer
 * @warning In debug mode (--debug option), SIGINT causes immediate exit bypassing self-pipe for ^C responsiveness
 * 
 * @see async_event() for event processing in main loop context
 * @see send_event() for self-pipe event writing (async-signal-safe)
 * @see main() for signal handler installation via sigaction()
 * @see signal(7) and signal-safety(7) man pages for async-signal-safe function restrictions
 * 
 * EXAMPLE USAGE:
 * @code
 * // Signal handler installed in main():
 * struct sigaction sigact;
 * sigact.sa_handler = sig_handler;
 * sigact.sa_flags = 0;
 * sigemptyset(&sigact.sa_mask);
 * sigaction(SIGHUP, &sigact, NULL);  // Install handler for config reload
 * 
 * // When user sends "kill -HUP <pid>":
 * // 1. OS delivers SIGHUP to process
 * // 2. sig_handler(SIGHUP) executes in signal context
 * // 3. Translates to EVENT_RELOAD and writes to self-pipe
 * // 4. Returns immediately
 * // 5. Main loop poll() wakes on pipe readable
 * // 6. async_event() reads EVENT_RELOAD and calls clear_cache_and_reload()
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Writes event descriptor to self-pipe via send_event()
 * - TCP children exit immediately on SIGALRM
 * - Preserves and restores errno
 * - In debug mode, SIGINT causes immediate daemon exit
 * 
 * THREAD SAFETY:
 * Async-signal-safe (can be invoked during any non-atomic operation). Uses only write() system call
 * via send_event() with NULL message parameter.
 */
static void sig_handler(int sig)
{
  if (pid == 0)
    {
      /* ignore anything other than TERM during startup
	 and in helper proc. (helper ignore TERM too) */
      if (sig == SIGTERM || sig == SIGINT)
	exit(EC_MISC);
    }
  else if (pid != getpid())
    {
      /* alarm is used to kill TCP children after a fixed time. */
      if (sig == SIGALRM)
	_exit(0);
    }
  else
    {
      /* master process */
      int event, errsave = errno;
      
      if (sig == SIGHUP)
	event = EVENT_RELOAD;
      else if (sig == SIGCHLD)
	event = EVENT_CHILD;
      else if (sig == SIGALRM)
	event = EVENT_ALARM;
      else if (sig == SIGTERM)
	event = EVENT_TERM;
      else if (sig == SIGUSR1)
	event = EVENT_DUMP;
      else if (sig == SIGUSR2)
	event = EVENT_REOPEN;
      else if (sig == SIGINT)
	{
	  /* Handle SIGINT normally in debug mode, so
	     ctrl-c continues to operate. */
	  if (option_bool(OPT_DEBUG))
	    exit(EC_MISC);
	  else
	    event = EVENT_TIME;
	}
      else
	return;

      send_event(pipewrite, event, 0, NULL); 
      errno = errsave;
    }
}

/**
 * @brief Schedule alarm signal for future event or queue immediate callback
 * 
 * @detailed
 * Schedules a SIGALRM signal to be delivered at the specified event time using alarm() system call.
 * If the event is immediate (now == 0) or event time has already passed, queues an immediate
 * EVENT_ALARM via send_event() to the self-pipe instead of using alarm(). This function is primarily
 * used for DHCP lease expiry timers, Router Advertisement periodic transmission, and cache TTL
 * expiration timeouts that need to be checked at specific future times.
 * 
 * The alarm() call sets a timer that will deliver SIGALRM after the calculated number of seconds
 * (difftime(event, now)). The signal handler sig_handler() will then send EVENT_ALARM through the
 * self-pipe, which async_event() will process in the main loop context.
 * 
 * @param event Absolute time_t when alarm should fire (seconds since epoch), or 0 to disable pending alarm
 * @param now Current time_t (seconds since epoch), or 0 to force immediate EVENT_ALARM delivery
 * 
 * @note Special case handling: alarm(0) cancels pending alarm, alarm(-ve) is undefined, so we avoid
 *       calling alarm() with invalid values and use send_event() directly for immediate callbacks
 * @note Only one alarm() can be pending system-wide per process - calling send_alarm() replaces
 *       any previously scheduled alarm
 * 
 * @warning Not thread-safe - modifies process-wide alarm() state
 * @warning Relies on sig_handler() being installed for SIGALRM signal
 * 
 * @see sig_handler() for SIGALRM signal handling
 * @see async_event() for EVENT_ALARM processing in main loop
 * @see send_event() for immediate event queueing
 * @see alarm(2) man page for POSIX alarm() semantics
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * time_t lease_expiry = now + 3600; // Lease expires in 1 hour
 * send_alarm(lease_expiry, now); // Schedule SIGALRM in 3600 seconds
 * 
 * // For immediate callback:
 * send_alarm(0, 0); // Queues immediate EVENT_ALARM via self-pipe
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Modifies process alarm() timer (only one alarm can be pending)
 * - May write EVENT_ALARM to self-pipe if event is immediate or overdue
 * 
 * THREAD SAFETY:
 * Not thread-safe. Uses process-global alarm() state and writes to self-pipe.
 */
void send_alarm(time_t event, time_t now)
{
  if (now == 0 || event != 0)
    {
      /* alarm(0) or alarm(-ve) doesn't do what we want.... */
      if ((now == 0 || difftime(event, now) <= 0.0))
	send_event(pipewrite, EVENT_ALARM, 0, NULL);
      else 
	alarm((unsigned)difftime(event, now)); 
    }
}

/**
 * @brief Queue an event to the main loop via self-pipe
 * 
 * @detailed
 * Convenience wrapper around send_event() that queues an event with no associated data or message
 * to the self-pipe for processing by async_event() in the main event loop. This function is used
 * by subsystems to trigger asynchronous event processing without going through signal handlers.
 * The event is written to the non-blocking pipe and will be read by the main loop on next poll() iteration.
 * 
 * Common event types: EVENT_RELOAD (config reload), EVENT_DUMP (cache dump), EVENT_TERM (shutdown),
 * EVENT_ALARM (timer expiry), EVENT_NEWADDR (interface address change), EVENT_NEWROUTE (routing change).
 * 
 * @param event Event code from event type enum (see dnsmasq.h event definitions)
 * 
 * @note No return value - writes to non-blocking pipe which either succeeds immediately or fails silently
 * @note The pipe is sized >= PIPE_BUF so atomic writes of struct event_desc are guaranteed on Linux
 * 
 * @warning Must be called with pipewrite file descriptor initialized (set up during daemon startup)
 * @warning Event data and msg fields will be 0/NULL - use send_event() directly for events with payloads
 * 
 * @see send_event() for full event queuing with data and message
 * @see async_event() for event processing in main loop context
 * @see sig_handler() for signal-triggered event queuing
 * 
 * EXAMPLE USAGE:
 * @code
 * // Trigger cache dump from diagnostic code
 * queue_event(EVENT_DUMP);
 * 
 * // Request configuration reload from monitoring code
 * queue_event(EVENT_RELOAD);
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Writes struct event_desc to self-pipe (non-blocking write)
 * - Main loop will process event on next poll() wake-up
 * 
 * THREAD SAFETY:
 * Not thread-safe. Writes to process-global self-pipe without synchronization.
 */
void queue_event(int event)
{
  send_event(pipewrite, event, 0, NULL);
}

/**
 * @brief Send event with optional data and message to file descriptor
 * 
 * @detailed
 * Constructs a struct event_desc with specified event code, data payload, and optional message string,
 * then atomically writes it to the given file descriptor using writev(). Typically writes to the self-pipe
 * (pipewrite fd) for delivery to main loop via async_event(), or to error pipe (err_pipe) for fatal errors
 * during initialization. The pipe write is non-blocking and struct event_desc is smaller than PIPE_BUF
 * (4096 bytes on Linux) ensuring atomic writes that either succeed completely or fail without partial writes.
 * 
 * Uses scatter-gather I/O (writev) with two iovec buffers: first contains struct event_desc header with
 * event/data/msg_sz fields, second contains optional message string. This allows kernel to write both
 * atomically in single system call. Retries write on EINTR (interrupted by signal).
 * 
 * Special case: if fd == -1, calls fatal_event() directly for synchronous fatal error handling during
 * daemon initialization before self-pipe is available.
 * 
 * @param fd File descriptor to write event to (typically pipewrite for self-pipe, or err_pipe for errors,
 *           or -1 for direct fatal_event() call)
 * @param event Event code from event type enum (EVENT_RELOAD, EVENT_TERM, EVENT_ALARM, EVENT_DIE, etc.)
 * @param data Integer data payload associated with event (e.g., signal number, errno value, child PID)
 * @param msg Optional null-terminated message string providing details (e.g., error description), or NULL
 *            if no message. WARNING: message memory is leaked after read_event() - only use for fatal errors
 * 
 * @note Uses writev() for atomic scatter-gather write of header + message in single system call
 * @note Retries on EINTR but not on other errors - non-blocking pipe either succeeds or drops event
 * @note struct event_desc is < PIPE_BUF so writes are atomic on POSIX systems
 * 
 * @warning Message memory passed via msg parameter is leaked after read_event() consumes it - only use
 *          for fatal error messages where daemon will exit immediately
 * @warning If fd is non-blocking (as self-pipe should be), write may fail with EAGAIN/EWOULDBLOCK if pipe
 *          full - event will be silently dropped
 * @warning Never pass untrusted input as msg parameter - no bounds checking on message length
 * 
 * @see queue_event() for convenient wrapper with no data/message
 * @see async_event() for event consumption in main loop
 * @see read_event() for reading event from pipe
 * @see fatal_event() for fatal error event processing
 * @see writev(2) man page for scatter-gather I/O semantics
 * 
 * EXAMPLE USAGE:
 * @code
 * // Send reload event from signal handler (async-signal-safe)
 * send_event(pipewrite, EVENT_RELOAD, 0, NULL);
 * 
 * // Send error event with errno and message
 * send_event(err_pipe, EVENT_FORK_ERR, errno, "Failed to fork helper");
 * 
 * // Send child exit event with exit status
 * send_event(pipewrite, EVENT_EXITED, exit_status, NULL);
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Writes struct event_desc (and optional message) to file descriptor using writev()
 * - If fd == -1, calls fatal_event() which may terminate daemon
 * - Retries write if interrupted by signal (EINTR)
 * 
 * THREAD SAFETY:
 * Async-signal-safe when msg is NULL and fd is valid (no malloc, no mutex, only writev system call).
 * Can be safely called from signal handlers with NULL message parameter.
 */
void send_event(int fd, int event, int data, char *msg)
{
  struct event_desc ev;
  struct iovec iov[2];

  ev.event = event;
  ev.data = data;
  ev.msg_sz = msg ? strlen(msg) : 0;
  
  iov[0].iov_base = &ev;
  iov[0].iov_len = sizeof(ev);
  iov[1].iov_base = msg;
  iov[1].iov_len = ev.msg_sz;
  
  /* error pipe, debug mode. */
  if (fd == -1)
    fatal_event(&ev, msg);
  else
    /* pipe is non-blocking and struct event_desc is smaller than
       PIPE_BUF, so this either fails or writes everything */
    while (writev(fd, iov, msg ? 2 : 1) == -1 && errno == EINTR);
}

/**
 * @brief Read event descriptor and optional message from pipe file descriptor
 * 
 * @detailed
 * Reads a struct event_desc from the given file descriptor (typically the self-pipe piperead), followed
 * by optional message string if ev.msg_sz > 0. Uses read_write() utility for reliable read with retry on
 * EINTR. Allocates memory for message string via malloc() if message present - this memory is intentionally
 * leaked after use (only safe for fatal error messages where daemon exits immediately).
 * 
 * Returns 1 on success with evp populated and *msg set to allocated string (or NULL if no message),
 * returns 0 on read failure (pipe closed or error). Caller is responsible for checking event type and
 * processing via switch statement in async_event().
 * 
 * @param fd File descriptor to read from (typically piperead from self-pipe setup in main())
 * @param evp Pointer to struct event_desc to populate with event/data/msg_sz fields read from pipe
 * @param msg Pointer to char* which will be set to malloc'd message string if msg_sz > 0, or NULL if no message
 * 
 * @return 1 on successful read of event descriptor (with or without message), 0 on read failure
 * @retval 1 Event successfully read into evp, message (if any) allocated and assigned to *msg
 * @retval 0 Failed to read event descriptor (pipe closed, error, or partial read) - evp/msg undefined
 * 
 * @note Message memory is intentionally leaked - only use for fatal error messages where daemon exits
 * @note Uses read_write() utility which retries on EINTR for robust signal-safe reading
 * @note Message buffer is null-terminated (extra byte allocated beyond msg_sz)
 * 
 * @warning Memory leak: allocated message buffer via malloc() is never freed - only use for fatal errors
 * @warning Partial reads fail silently - read_write() ensures atomic read of struct or fails completely
 * @warning No bounds checking on msg_sz - attacker controlling pipe could cause large malloc()
 * 
 * @see send_event() for writing events to pipe
 * @see async_event() for event processing after read_event() succeeds
 * @see read_write() in util.c for reliable read with EINTR retry
 * 
 * EXAMPLE USAGE:
 * @code
 * struct event_desc ev;
 * char *msg = NULL;
 * 
 * if (read_event(piperead, &ev, &msg)) {
 *     switch (ev.event) {
 *         case EVENT_RELOAD:
 *             clear_cache_and_reload(now);
 *             break;
 *         case EVENT_DIE:
 *             fatal_event(&ev, msg); // exits, msg memory leak acceptable
 *             break;
 *     }
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Reads sizeof(struct event_desc) bytes from file descriptor
 * - May allocate memory via malloc() for message string (intentionally leaked)
 * - Consumes one event from pipe (pipe is drained by each read_event() call)
 * 
 * THREAD SAFETY:
 * Not thread-safe. Reads from shared file descriptor without synchronization. Calls malloc() which
 * is not async-signal-safe.
 */
/* NOTE: the memory used to return msg is leaked: use msgs in events only
   to describe fatal errors. */
static int read_event(int fd, struct event_desc *evp, char **msg)
{
  char *buf;

  if (!read_write(fd, (unsigned char *)evp, sizeof(struct event_desc), 1))
    return 0;
  
  *msg = NULL;
  
  if (evp->msg_sz != 0 && 
      (buf = malloc(evp->msg_sz + 1)) &&
      read_write(fd, (unsigned char *)buf, evp->msg_sz, 1))
    {
      buf[evp->msg_sz] = 0;
      *msg = buf;
    }

  return 1;
}
    
/**
 * @brief Handle fatal error events requiring daemon termination or critical logging
 * 
 * @detailed
 * Processes fatal events queued by send_event() for main-context handling. Handles EVENT_DIE
 * (clean shutdown), EVENT_FORK_ERR (helper process fork failure), EVENT_PIPE_ERR (helper pipe
 * communication failure), EVENT_USER_ERR (setuid/setgid failure), EVENT_CAP_ERR (Linux capability
 * manipulation failure), and EVENT_PIDFILE (PID file write failure). All errors logged via die()
 * which terminates daemon with appropriate error message.
 * 
 * Event types: EVENT_DIE exits cleanly with code 0. All other events restore errno from ev->data,
 * log error message with die(), and terminate. Used for unrecoverable initialization errors that
 * cannot be handled in signal context or helper process.
 * 
 * @param ev Event descriptor containing event type and associated errno
 * @param msg Optional custom error message string (may be NULL for standard messages)
 * 
 * @note Called only from async_event() after read_event() delivers fatal events
 * @note Always terminates daemon (via exit(0) or die()) except for events removed from codebase
 * @warning No return - function always exits process
 * 
 * @see send_event() for fatal event queuing mechanism
 * @see async_event() for event dispatch
 * @see die() in dnsmasq.c for error logging and exit
 * 
 * EXAMPLE USAGE:
 * @code
 * // Helper process fork failure:
 * if (fork() == -1) {
 *   send_event(event_fd, EVENT_FORK_ERR, errno, NULL);
 *   // → async_event → read_event → fatal_event
 *   // → die("cannot fork helper: %s", strerror(errno))
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Logs fatal error message to syslog
 * - Terminates daemon process (exit() or die())
 * - May delete PID file on clean shutdown
 * 
 * THREAD SAFETY:
 * Not thread-safe. Terminates process, so concurrency irrelevant.
 */
static void fatal_event(struct event_desc *ev, char *msg)
{
  errno = ev->data;
  
  switch (ev->event)
    {
    case EVENT_DIE:
      exit(0);

    case EVENT_FORK_ERR:
      die(_("cannot fork into background: %s"), NULL, EC_MISC);

      /* fall through */
    case EVENT_PIPE_ERR:
      die(_("failed to create helper: %s"), NULL, EC_MISC);

      /* fall through */
    case EVENT_CAP_ERR:
      die(_("setting capabilities failed: %s"), NULL, EC_MISC);

      /* fall through */
    case EVENT_USER_ERR:
      die(_("failed to change user-id to %s: %s"), msg, EC_MISC);

      /* fall through */
    case EVENT_GROUP_ERR:
      die(_("failed to change group-id to %s: %s"), msg, EC_MISC);

      /* fall through */
    case EVENT_PIDFILE:
      die(_("failed to open pidfile %s: %s"), msg, EC_FILE);

      /* fall through */
    case EVENT_LOG_ERR:
      die(_("cannot open log %s: %s"), msg, EC_FILE);

      /* fall through */
    case EVENT_LUA_ERR:
      die(_("failed to load Lua script: %s"), msg, EC_MISC);

      /* fall through */
    case EVENT_TFTP_ERR:
      die(_("TFTP directory %s inaccessible: %s"), msg, EC_FILE);

      /* fall through */
    case EVENT_TIME_ERR:
      die(_("cannot create timestamp file %s: %s" ), msg, EC_BADCONF);
    }
}

/**
 * @brief Process queued events from self-pipe in main loop context
 * 
 * @detailed
 * Reads and processes events from the self-pipe that were queued by sig_handler() (for signals) or
 * queue_event() (for async subsystem events). Provides safe signal processing by deferring signal
 * handling from async-signal-unsafe signal context to main event loop where full API is available.
 * 
 * Handles events: EVENT_RELOAD/EVENT_INIT (config reload via clear_cache_and_reload), EVENT_DUMP
 * (cache dump to syslog), EVENT_ALARM (DHCP lease expiry, RA periodic sending), EVENT_CHILD (reap
 * TCP children via waitpid), EVENT_KILLED/EVENT_EXITED/EVENT_EXEC_ERR (helper script errors),
 * EVENT_REOPEN (log rotation), EVENT_NEWADDR (interface address change via newaddress()), EVENT_NEWROUTE
 * (routing table change), EVENT_TIME (DNSSEC time check), EVENT_TERM (graceful shutdown with lease flush),
 * EVENT_DIE/EVENT_USER_ERR/EVENT_LUA_ERR (fatal errors via fatal_event()).
 * 
 * Uses read_event() to atomically read struct event_desc from pipe, then large switch statement to
 * dispatch to appropriate handler. Some events like EVENT_ALARM trigger DHCP lease pruning and file
 * updates, EVENT_CHILD reaps zombie processes from daemon->tcp_pids[] array.
 * 
 * @param pipe File descriptor for reading events (typically piperead from self-pipe setup in main())
 * @param now Current time from dnsmasq_time() for timestamp-dependent operations (lease expiry, TTL)
 * 
 * @note Called from main event loop when poll() indicates pipe is readable
 * @note Message memory from read_event() is intentionally leaked except for fatal error messages
 * @note Multiple events may be queued - main loop calls repeatedly while pipe readable
 * 
 * @warning Must be called from main loop context, not signal handlers or child processes
 * @warning EVENT_TERM never returns - flushes leases, kills children, and exits daemon
 * 
 * @see sig_handler() for signal-triggered event queuing
 * @see read_event() for reading events from pipe
 * @see clear_cache_and_reload() for EVENT_RELOAD/EVENT_INIT processing
 * @see newaddress() in network.c for EVENT_NEWADDR interface change handling
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main event loop after poll() returns:
 * if (poll_check(piperead, POLLIN))
 *     async_event(piperead, now);  // Process all queued events
 * @endcode
 * 
 * SIDE EFFECTS:
 * - EVENT_RELOAD: Clears DNS cache, reloads hosts/resolv files, bumps SOA serial
 * - EVENT_DUMP: Writes cache statistics to syslog
 * - EVENT_ALARM: Prunes expired DHCP leases, updates lease file, sends periodic RA
 * - EVENT_CHILD: Reaps terminated TCP child processes from tcp_pids array
 * - EVENT_TERM: Kills all TCP children, flushes lease file, exits daemon
 * - EVENT_REOPEN: Closes and reopens log file for rotation
 * - EVENT_NEWADDR: Updates interface address list via newaddress()
 * - EVENT_NEWROUTE: Resends queued queries, re-reads resolv file
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon state including tcp_pids, cache, lease database.
 */	
static void async_event(int pipe, time_t now)
{
  pid_t p;
  struct event_desc ev;
  int i, check = 0;
  char *msg;
  
  /* NOTE: the memory used to return msg is leaked: use msgs in events only
     to describe fatal errors. */
  
  if (read_event(pipe, &ev, &msg))
    switch (ev.event)
      {
      case EVENT_RELOAD:
	daemon->soa_sn++; /* Bump zone serial, as it may have changed. */
	
	/* fall through */
	
      case EVENT_INIT:
	clear_cache_and_reload(now);
	
	if (daemon->port != 0)
	  {
	    if (daemon->resolv_files && option_bool(OPT_NO_POLL))
	      {
		reload_servers(daemon->resolv_files->name);
		check = 1;
	      }

	    if (daemon->servers_file)
	      {
		read_servers_file();
		check = 1;
	      }

	    if (check)
	      check_servers(0);
	  }

#ifdef HAVE_DHCP
	rerun_scripts();
#endif
	break;
	
      case EVENT_DUMP:
	if (daemon->port != 0)
	  dump_cache(now);
	break;
	
      case EVENT_ALARM:
#ifdef HAVE_DHCP
	if (daemon->dhcp || daemon->doing_dhcp6)
	  {
	    lease_prune(NULL, now);
	    lease_update_file(now);
	  }
#ifdef HAVE_DHCP6
	else if (daemon->doing_ra)
	  /* Not doing DHCP, so no lease system, manage alarms for ra only */
	    send_alarm(periodic_ra(now), now);
#endif
#endif
	break;
		
      case EVENT_CHILD:
	/* See Stevens 5.10 */
	while ((p = waitpid(-1, NULL, WNOHANG)) != 0)
	  if (p == -1)
	    {
	      if (errno != EINTR)
		break;
	    }      
	  else 
	    for (i = 0 ; i < MAX_PROCS; i++)
	      if (daemon->tcp_pids[i] == p)
		daemon->tcp_pids[i] = 0;
	break;
	
#if defined(HAVE_SCRIPT)	
      case EVENT_KILLED:
	my_syslog(LOG_WARNING, _("script process killed by signal %d"), ev.data);
	break;

      case EVENT_EXITED:
	my_syslog(LOG_WARNING, _("script process exited with status %d"), ev.data);
	break;

      case EVENT_EXEC_ERR:
	my_syslog(LOG_ERR, _("failed to execute %s: %s"), 
		  daemon->lease_change_command, strerror(ev.data));
	break;

      case EVENT_SCRIPT_LOG:
	my_syslog(MS_SCRIPT | LOG_DEBUG, "%s", msg ? msg : "");
        free(msg);
	msg = NULL;
	break;

	/* necessary for fatal errors in helper */
      case EVENT_USER_ERR:
      case EVENT_DIE:
      case EVENT_LUA_ERR:
	fatal_event(&ev, msg);
	break;
#endif

      case EVENT_REOPEN:
	/* Note: this may leave TCP-handling processes with the old file still open.
	   Since any such process will die in CHILD_LIFETIME or probably much sooner,
	   we leave them logging to the old file. */
	if (daemon->log_file != NULL)
	  log_reopen(daemon->log_file);
	break;

      case EVENT_NEWADDR:
	newaddress(now);
	break;

      case EVENT_NEWROUTE:
	resend_query();
	/* Force re-reading resolv file right now, for luck. */
	poll_resolv(0, 1, now);
	break;

      case EVENT_TIME:
#ifdef HAVE_DNSSEC
	if (daemon->dnssec_no_time_check && option_bool(OPT_DNSSEC_VALID) && option_bool(OPT_DNSSEC_TIME))
	  {
	    my_syslog(LOG_INFO, _("now checking DNSSEC signature timestamps"));
	    daemon->dnssec_no_time_check = 0;
	    clear_cache_and_reload(now);
	  }
#endif
	break;
	
      case EVENT_TERM:
	/* Knock all our children on the head. */
	for (i = 0; i < MAX_PROCS; i++)
	  if (daemon->tcp_pids[i] != 0)
	    kill(daemon->tcp_pids[i], SIGALRM);
	
#if defined(HAVE_SCRIPT) && defined(HAVE_DHCP)
	/* handle pending lease transitions */
	if (daemon->helperfd != -1)
	  {
	    /* block in writes until all done */
	    if ((i = fcntl(daemon->helperfd, F_GETFL)) != -1)
	      while(retry_send(fcntl(daemon->helperfd, F_SETFL, i & ~O_NONBLOCK)));
	    do {
	      helper_write();
	    } while (!helper_buf_empty() || do_script_run(now));
	    close(daemon->helperfd);
	  }
#endif
	
	if (daemon->lease_stream)
	  fclose(daemon->lease_stream);

#ifdef HAVE_DNSSEC
	/* update timestamp file on TERM if time is considered valid */
	if (daemon->back_to_the_future)
	  {
	     if (utimes(daemon->timestamp_file, NULL) == -1)
		my_syslog(LOG_ERR, _("failed to update mtime on %s: %s"), daemon->timestamp_file, strerror(errno));
	  }
#endif

	if (daemon->runfile)
	  unlink(daemon->runfile);

#ifdef HAVE_DUMPFILE
	if (daemon->dumpfd != -1)
	  close(daemon->dumpfd);
#endif
	
	my_syslog(LOG_INFO, _("exiting on receipt of SIGTERM"));
	flush_log();
	exit(EC_GOOD);
      }
}

/**
 * @brief Check resolv.conf for changes and reload upstream DNS servers if modified
 * 
 * @detailed
 * Monitors /etc/resolv.conf (or custom resolv file via --resolv-file) for modifications by comparing
 * file mtime against daemon->last_resolv timestamp. If file changed (or force==1), rereads nameserver
 * entries and updates daemon->servers list. Called periodically from main loop (every ~1 second) or
 * immediately via EVENT_NEWROUTE/inotify. If do_reload==1, also triggers cache clear and hosts reload.
 * 
 * Handles multiple resolv files if configured, iterating through daemon->resolv_files list. Skips
 * reload if --no-poll option set. Updates daemon->last_resolv timestamp after successful check.
 * 
 * @param force If 1, force reload even if mtime unchanged (used on startup and explicit triggers)
 * @param do_reload If 1, also clear cache and reload hosts files via clear_cache_and_reload()
 * @param now Current time from dnsmasq_time() for timestamp comparisons
 * 
 * @note Only reloads if file mtime changed or force==1
 * @note Multiple resolv files supported via --resolv-file option repeated
 * @note Respects --no-poll option to disable automatic reload checks
 * 
 * @see clear_cache_and_reload() for full configuration reload
 * @see check_servers() in option.c for upstream server list validation
 * 
 * EXAMPLE USAGE:
 * @code
 * // Periodic check in main loop:
 * if (difftime(now, daemon->last_resolv) > 1.0)
 *     poll_resolv(0, 0, now);  // Check for changes, no forced reload
 * 
 * // Force reload on network change:
 * poll_resolv(1, 1, now);  // Force reload with cache clear
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Rereads resolv.conf and updates daemon->servers list
 * - If do_reload==1, clears DNS cache and reloads hosts files
 * - Updates daemon->last_resolv timestamp
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->servers list without synchronization.
 */
static void poll_resolv(int force, int do_reload, time_t now)
{
  struct resolvc *res, *latest;
  struct stat statbuf;
  time_t last_change = 0;
  /* There may be more than one possible file. 
     Go through and find the one which changed _last_.
     Warn of any which can't be read. */

  if (daemon->port == 0 || option_bool(OPT_NO_POLL))
    return;
  
  for (latest = NULL, res = daemon->resolv_files; res; res = res->next)
    if (stat(res->name, &statbuf) == -1)
      {
	if (force)
	  {
	    res->mtime = 0; 
	    continue;
	  }

	if (!res->logged)
	  my_syslog(LOG_WARNING, _("failed to access %s: %s"), res->name, strerror(errno));
	res->logged = 1;
	
	if (res->mtime != 0)
	  { 
	    /* existing file evaporated, force selection of the latest
	       file even if its mtime hasn't changed since we last looked */
	    poll_resolv(1, do_reload, now);
	    return;
	  }
      }
    else
      {
	res->logged = 0;
	if (force || (statbuf.st_mtime != res->mtime || statbuf.st_ino != res->ino))
          {
            res->mtime = statbuf.st_mtime;
	    res->ino = statbuf.st_ino;
	    if (difftime(statbuf.st_mtime, last_change) > 0.0)
	      {
		last_change = statbuf.st_mtime;
		latest = res;
	      }
	  }
      }
  
  if (latest)
    {
      static int warned = 0;
      if (reload_servers(latest->name))
	{
	  my_syslog(LOG_INFO, _("reading %s"), latest->name);
	  warned = 0;
	  check_servers(0);
	  if (option_bool(OPT_RELOAD) && do_reload)
	    clear_cache_and_reload(now);
	}
      else 
	{
	  /* If we're delaying things, we don't call check_servers(), but 
	     reload_servers() may have deleted some servers, rendering the server_array
	     invalid, so just rebuild that here. Once reload_servers() succeeds,
	     we call check_servers() above, which calls build_server_array itself. */
	  build_server_array();
	  latest->mtime = 0;
	  if (!warned)
	    {
	      my_syslog(LOG_WARNING, _("no servers found in %s, will retry"), latest->name);
	      warned = 1;
	    }
	}
    }
}       

/**
 * @brief Clear DNS cache and reload all configuration files
 * 
 * @detailed
 * Comprehensive configuration reload triggered by SIGHUP signal or explicit API call. Clears entire
 * DNS cache via cache_start_insert()/cache_end_insert(), reloads /etc/hosts and additional hosts files,
 * reloads /etc/resolv.conf for upstream servers, reloads DHCP host configuration, and logs reload
 * completion. Used for dynamic configuration updates without daemon restart.
 * 
 * Operations performed: (1) Clear DNS cache completely, (2) reload hosts files via read_hosts(),
 * (3) reload resolv.conf via poll_resolv(), (4) reload DHCP hosts if HAVE_DHCP, (5) recheck
 * upstream servers via check_servers(), (6) log "cleared cache" message.
 * 
 * @param now Current time from dnsmasq_time() for timestamp operations
 * 
 * @note Called from async_event() for EVENT_RELOAD and EVENT_INIT
 * @note Preserves daemon state except cached data and file-sourced configuration
 * @note Does NOT reload command-line options or main config file (requires restart)
 * 
 * @see async_event() for EVENT_RELOAD handling
 * @see poll_resolv() for resolv.conf reload
 * @see read_hosts() in cache.c for hosts file reload
 * 
 * EXAMPLE USAGE:
 * @code
 * // Triggered by user sending SIGHUP:
 * // kill -HUP <dnsmasq_pid>
 * // → sig_handler → EVENT_RELOAD → async_event → clear_cache_and_reload
 * 
 * // Programmatic reload:
 * clear_cache_and_reload(dnsmasq_time());
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Clears entire DNS cache (all cached RRs deleted)
 * - Reloads /etc/hosts and --addn-hosts files
 * - Reloads /etc/resolv.conf upstream server list
 * - Reloads DHCP static host configurations
 * - Logs "cleared cache" message to syslog
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies global cache and configuration state.
 */
void clear_cache_and_reload(time_t now)
{
  (void)now;

  if (daemon->port != 0)
    cache_reload();
  
#ifdef HAVE_DHCP
  if (daemon->dhcp || daemon->doing_dhcp6)
    {
      if (option_bool(OPT_ETHERS))
	dhcp_read_ethers();
      reread_dhcp();
      dhcp_update_configs(daemon->dhcp_conf);
      lease_update_from_configs(); 
      lease_update_file(now); 
      lease_update_dns(1);
    }
#ifdef HAVE_DHCP6
  else if (daemon->doing_ra)
    /* Not doing DHCP, so no lease system, manage 
       alarms for ra only */
    send_alarm(periodic_ra(now), now);
#endif
#endif
}

/**
 * @brief Register all DNS listener sockets with poll system
 * 
 * @detailed
 * Iterates through all configured DNS listener sockets and registers each with poll_listen() for
 * read event monitoring. Covers wildcard listeners (0.0.0.0, ::) and interface-specific listeners.
 * Called during daemon initialization and after interface changes (EVENT_NEWADDR). Enables DNS
 * query reception on UDP port 53 (and TCP 53 if configured).
 * 
 * Walks daemon->listeners linked list of struct listener, calling poll_listen(fd, POLLIN) for each
 * socket file descriptor. TCP listeners registered separately with poll_accept().
 * 
 * @note Called from main() during startup and from async_event() on interface changes
 * @note TCP DNS listeners handled separately via poll_accept() for connection-oriented protocol
 * 
 * @see poll_listen() in poll.c for registration mechanism
 * @see check_dns_listeners() for processing ready DNS sockets
 * @see create_bound_listeners() in network.c for listener creation
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon startup in main():
 * create_bound_listeners(0);  // Create listener sockets
 * set_dns_listeners();        // Register with poll
 * 
 * // After interface address change:
 * // netlink notification → EVENT_NEWADDR → async_event
 * set_dns_listeners();        // Re-register updated listeners
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Registers file descriptors with poll system (modifies global poll state)
 * - Does NOT create sockets (assumes pre-existing listeners)
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies global poll registration state.
 */
static void set_dns_listeners(void)
{
  struct serverfd *serverfdp;
  struct listener *listener;
  struct randfd_list *rfl;
  int i;
  
#ifdef HAVE_TFTP
  int  tftp = 0;
  struct tftp_transfer *transfer;
  if (!option_bool(OPT_SINGLE_PORT))
    for (transfer = daemon->tftp_trans; transfer; transfer = transfer->next)
      {
	tftp++;
	poll_listen(transfer->sockfd, POLLIN);
      }
#endif
  
  for (serverfdp = daemon->sfds; serverfdp; serverfdp = serverfdp->next)
    poll_listen(serverfdp->fd, POLLIN);
    
  for (i = 0; i < daemon->numrrand; i++)
    if (daemon->randomsocks[i].refcount != 0)
      poll_listen(daemon->randomsocks[i].fd, POLLIN);

  /* Check overflow random sockets too. */
  for (rfl = daemon->rfl_poll; rfl; rfl = rfl->next)
    poll_listen(rfl->rfd->fd, POLLIN);
  
  /* check to see if we have free tcp process slots. */
  for (i = MAX_PROCS - 1; i >= 0; i--)
    if (daemon->tcp_pids[i] == 0 && daemon->tcp_pipes[i] == -1)
      break;

  for (listener = daemon->listeners; listener; listener = listener->next)
    {
      if (listener->fd != -1)
	poll_listen(listener->fd, POLLIN);
      
      /* Only listen for TCP connections when a process slot
	 is available. Death of a child goes through the select loop, so
	 we don't need to explicitly arrange to wake up here,
	 we'll be called again when a slot becomes available. */
      if  (listener->tcpfd != -1 && i >= 0)
	poll_listen(listener->tcpfd, POLLIN);
      
#ifdef HAVE_TFTP
      /* tftp == 0 in single-port mode. */
      if (tftp <= daemon->tftp_max && listener->tftpfd != -1)
	poll_listen(listener->tftpfd, POLLIN);
#endif
    }
  
  if (!option_bool(OPT_DEBUG))
    for (i = 0; i < MAX_PROCS; i++)
      if (daemon->tcp_pipes[i] != -1)
	poll_listen(daemon->tcp_pipes[i], POLLIN);
}

/**
 * @brief Process ready DNS listener sockets and dispatch queries
 * 
 * @detailed
 * Checks all DNS listener sockets for pending data via poll_check(), reads DNS queries from ready
 * UDP sockets, and dispatches to forward.c receive_query() for processing. Handles both IPv4 and
 * IPv6 listeners. Also checks TCP listener sockets for new connections and existing TCP connections
 * for query data. Core DNS query ingestion point called from main event loop.
 * 
 * For each listener: (1) poll_check(fd, POLLIN) tests readiness, (2) recvmsg() reads UDP datagram,
 * (3) extract source address and interface index from ancillary data, (4) call receive_query() in
 * forward.c with query packet. TCP queries handled via poll_accept() and TCP state machine.
 * 
 * @param now Current time from dnsmasq_time() for query timestamp
 * 
 * @note Called from main event loop while(1) after do_poll() returns
 * @note Handles ancillary data (IP_PKTINFO/IPV6_PKTINFO) for source interface tracking
 * @note UDP queries dispatched immediately, TCP queries buffered until complete
 * 
 * @see receive_query() in forward.c for query processing entry point
 * @see set_dns_listeners() for listener registration
 * @see poll_check() in poll.c for readiness testing
 * 
 * EXAMPLE USAGE:
 * @code
 * // Main event loop in main():
 * while (1) {
 *   do_poll(timeout);           // Wait for events
 *   check_dns_listeners(now);   // Process ready DNS sockets
 *   // ... check other service listeners
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Reads from DNS listener sockets
 * - Allocates forward records (frec) via receive_query()
 * - May send DNS responses immediately for cached queries
 * - Logs query reception if --log-queries enabled
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies global forward record state.
 */
static void check_dns_listeners(time_t now)
{
  struct serverfd *serverfdp;
  struct listener *listener;
  struct randfd_list *rfl;
  int i;
  int pipefd[2];
  
  for (serverfdp = daemon->sfds; serverfdp; serverfdp = serverfdp->next)
    if (poll_check(serverfdp->fd, POLLIN))
      reply_query(serverfdp->fd, now);
  
  for (i = 0; i < daemon->numrrand; i++)
    if (daemon->randomsocks[i].refcount != 0 && 
	poll_check(daemon->randomsocks[i].fd, POLLIN))
      reply_query(daemon->randomsocks[i].fd, now);

  /* Check overflow random sockets too. */
  for (rfl = daemon->rfl_poll; rfl; rfl = rfl->next)
    if (poll_check(rfl->rfd->fd, POLLIN))
      reply_query(rfl->rfd->fd, now);

  /* Races. The child process can die before we read all of the data from the
     pipe, or vice versa. Therefore send tcp_pids to zero when we wait() the 
     process, and tcp_pipes to -1 and close the FD when we read the last
     of the data - indicated by cache_recv_insert returning zero.
     The order of these events is indeterminate, and both are needed
     to free the process slot. Once the child process has gone, poll()
     returns POLLHUP, not POLLIN, so have to check for both here. */
  if (!option_bool(OPT_DEBUG))
    for (i = 0; i < MAX_PROCS; i++)
      if (daemon->tcp_pipes[i] != -1 &&
	  poll_check(daemon->tcp_pipes[i], POLLIN | POLLHUP) &&
	  !cache_recv_insert(now, daemon->tcp_pipes[i]))
	{
	  close(daemon->tcp_pipes[i]);
	  daemon->tcp_pipes[i] = -1;	
	}
	
  for (listener = daemon->listeners; listener; listener = listener->next)
    {
      if (listener->fd != -1 && poll_check(listener->fd, POLLIN))
	receive_query(listener, now); 
      
#ifdef HAVE_TFTP     
      if (listener->tftpfd != -1 && poll_check(listener->tftpfd, POLLIN))
	tftp_request(listener, now);
#endif

      /* check to see if we have a free tcp process slot.
	 Note that we can't assume that because we had
	 at least one a poll() time, that we still do.
	 There may be more waiting connections after
	 poll() returns then free process slots. */
      for (i = MAX_PROCS - 1; i >= 0; i--)
	if (daemon->tcp_pids[i] == 0 && daemon->tcp_pipes[i] == -1)
	  break;

      if (listener->tcpfd != -1 && i >= 0 && poll_check(listener->tcpfd, POLLIN))
	{
	  int confd, client_ok = 1;
	  struct irec *iface = NULL;
	  pid_t p;
	  union mysockaddr tcp_addr;
	  socklen_t tcp_len = sizeof(union mysockaddr);

	  while ((confd = accept(listener->tcpfd, NULL, NULL)) == -1 && errno == EINTR);
	  
	  if (confd == -1)
	    continue;
	  
	  if (getsockname(confd, (struct sockaddr *)&tcp_addr, &tcp_len) == -1)
	    {
	      close(confd);
	      continue;
	    }
	  
	  /* Make sure that the interface list is up-to-date.
	     
	     We do this here as we may need the results below, and
	     the DNS code needs them for --interface-name stuff.

	     Multiple calls to enumerate_interfaces() per select loop are
	     inhibited, so calls to it in the child process (which doesn't select())
	     have no effect. This avoids two processes reading from the same
	     netlink fd and screwing the pooch entirely.
	  */
 
	  enumerate_interfaces(0);
	  
	  if (option_bool(OPT_NOWILD))
	    iface = listener->iface; /* May be NULL */
	  else 
	    {
	      int if_index;
	      char intr_name[IF_NAMESIZE];
	      
	      /* if we can find the arrival interface, check it's one that's allowed */
	      if ((if_index = tcp_interface(confd, tcp_addr.sa.sa_family)) != 0 &&
		  indextoname(listener->tcpfd, if_index, intr_name))
		{
		  union all_addr addr;
		  
		  if (tcp_addr.sa.sa_family == AF_INET6)
		    addr.addr6 = tcp_addr.in6.sin6_addr;
		  else
		    addr.addr4 = tcp_addr.in.sin_addr;
		  
		  for (iface = daemon->interfaces; iface; iface = iface->next)
		    if (iface->index == if_index &&
		        iface->addr.sa.sa_family == tcp_addr.sa.sa_family)
		      break;
		  
		  if (!iface && !loopback_exception(listener->tcpfd, tcp_addr.sa.sa_family, &addr, intr_name))
		    client_ok = 0;
		}
	      
	      if (option_bool(OPT_CLEVERBIND))
		iface = listener->iface; /* May be NULL */
	      else
		{
		  /* Check for allowed interfaces when binding the wildcard address:
		     we do this by looking for an interface with the same address as 
		     the local address of the TCP connection, then looking to see if that's
		     an allowed interface. As a side effect, we get the netmask of the
		     interface too, for localisation. */
		  
		  for (iface = daemon->interfaces; iface; iface = iface->next)
		    if (sockaddr_isequal(&iface->addr, &tcp_addr))
		      break;
		  
		  if (!iface)
		    client_ok = 0;
		}
	    }
	  
	  if (!client_ok)
	    {
	      shutdown(confd, SHUT_RDWR);
	      close(confd);
	    }
	  else if (!option_bool(OPT_DEBUG) && pipe(pipefd) == 0 && (p = fork()) != 0)
	    {
	      close(pipefd[1]); /* parent needs read pipe end. */
	      if (p == -1)
		close(pipefd[0]);
	      else
		{
#ifdef HAVE_LINUX_NETWORK
		  /* The child process inherits the netlink socket, 
		     which it never uses, but when the parent (us) 
		     uses it in the future, the answer may go to the 
		     child, resulting in the parent blocking
		     forever awaiting the result. To avoid this
		     the child closes the netlink socket, but there's
		     a nasty race, since the parent may use netlink
		     before the child has done the close.
		     
		     To avoid this, the parent blocks here until a 
		     single byte comes back up the pipe, which
		     is sent by the child after it has closed the
		     netlink socket. */
		  
		  unsigned char a;
		  read_write(pipefd[0], &a, 1, 1);
#endif

		  /* i holds index of free slot */
		  daemon->tcp_pids[i] = p;
		  daemon->tcp_pipes[i] = pipefd[0];
		}
	      close(confd);

	      /* The child can use up to TCP_MAX_QUERIES ids, so skip that many. */
	      daemon->log_id += TCP_MAX_QUERIES;
	    }
	  else
	    {
	      unsigned char *buff;
	      struct server *s; 
	      int flags;
	      struct in_addr netmask;
	      int auth_dns;
	   
	      if (iface)
		{
		  netmask = iface->netmask;
		  auth_dns = iface->dns_auth;
		}
	      else
		{
		  netmask.s_addr = 0;
		  auth_dns = 0;
		}

	      /* Arrange for SIGALRM after CHILD_LIFETIME seconds to
		 terminate the process. */
	      if (!option_bool(OPT_DEBUG))
		{
#ifdef HAVE_LINUX_NETWORK
		  /* See comment above re: netlink socket. */
		  unsigned char a = 0;

		  close(daemon->netlinkfd);
		  read_write(pipefd[1], &a, 1, 0);
#endif		  
		  alarm(CHILD_LIFETIME);
		  close(pipefd[0]); /* close read end in child. */
		  daemon->pipe_to_parent = pipefd[1];
		}

	      /* start with no upstream connections. */
	      for (s = daemon->servers; s; s = s->next)
		 s->tcpfd = -1; 
	      
	      /* The connected socket inherits non-blocking
		 attribute from the listening socket. 
		 Reset that here. */
	      if ((flags = fcntl(confd, F_GETFL, 0)) != -1)
		while(retry_send(fcntl(confd, F_SETFL, flags & ~O_NONBLOCK)));
	      
	      buff = tcp_request(confd, now, &tcp_addr, netmask, auth_dns);
	       
	      shutdown(confd, SHUT_RDWR);
	      close(confd);
	      
	      if (buff)
		free(buff);
	      
	      for (s = daemon->servers; s; s = s->next)
		if (s->tcpfd != -1)
		  {
		    shutdown(s->tcpfd, SHUT_RDWR);
		    close(s->tcpfd);
		  }
	      
	      if (!option_bool(OPT_DEBUG))
		{
		  close(daemon->pipe_to_parent);
		  flush_log();
		  _exit(0);
		}
	    }
	}
    }
}

#ifdef HAVE_DHCP
/**
 * @brief Create raw ICMP socket for ping-before-offer DHCP address testing
 * 
 * @detailed
 * Creates AF_INET raw socket with IPPROTO_ICMP for sending ICMP ECHO_REQUEST and receiving
 * ECHO_REPLY messages. Used by DHCP server to test if an IP address is already in use before
 * offering it in DHCPOFFER (ping-before-offer feature). Socket configured with SO_DONTROUTE to
 * avoid routing table lookup (local network only) and fixed via fix_fd() for close-on-exec.
 * 
 * Requires root/CAP_NET_RAW capability. Socket creation may fail if capabilities dropped too early
 * or on systems without raw socket support.
 * 
 * @return Socket file descriptor on success, -1 on failure
 * 
 * @retval >=0 Valid ICMP raw socket file descriptor
 * @retval -1 Socket creation failed (insufficient privileges or system error)
 * 
 * @note Called from icmp_ping() for each DHCP address conflict check
 * @note Socket typically opened/closed per ping operation, not persistent
 * @warning Requires CAP_NET_RAW capability on Linux or root on other systems
 * 
 * @see icmp_ping() for ICMP ECHO_REQUEST transmission using this socket
 * @see fix_fd() for close-on-exec flag setting
 * 
 * EXAMPLE USAGE:
 * @code
 * // DHCP server checking address before offer:
 * int icmp_fd = make_icmp_sock();
 * if (icmp_fd != -1) {
 *   if (icmp_ping(proposed_addr) == 1) {
 *     // Address in use, skip this IP
 *   }
 *   close(icmp_fd);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements ping-before-offer per RFC 2131 Section 3.1 paragraph 2 recommendation.
 * 
 * SIDE EFFECTS:
 * - Creates system file descriptor (consumes fd slot)
 * - Requires elevated privileges (CAP_NET_RAW or root)
 * 
 * THREAD SAFETY:
 * Thread-safe. Creates independent socket per call.
 */
int make_icmp_sock(void)
{
  int fd;
  int zeroopt = 0;

  if ((fd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) != -1)
    {
      if (!fix_fd(fd) ||
	  setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1)
	{
	  close(fd);
	  fd = -1;
	}
    }

  return fd;
}

/**
 * @brief Send ICMP ECHO_REQUEST and wait for reply to detect address conflicts
 * 
 * @detailed
 * Implements DHCP ping-before-offer by sending ICMP ECHO_REQUEST to proposed IP address and
 * waiting PING_WAIT seconds (default 3) for ECHO_REPLY. Returns 1 if reply received (address in
 * use), 0 if no reply (address available). Constructs raw ICMP packet with random ID, calculates
 * checksum, sends via sendto(), then waits in delay_dhcp() servicing DNS/TFTP but ignoring DHCP.
 * 
 * Platform-specific: Linux/Solaris create ephemeral socket via make_icmp_sock(), BSD uses
 * persistent daemon->dhcp_icmp_fd. Checksum computed as 16-bit one's complement sum per RFC 792.
 * 
 * @param addr IPv4 address to test (proposed DHCP lease address)
 * 
 * @return 1 if address responded (in use), 0 if no response (available) or error
 * 
 * @retval 1 ICMP ECHO_REPLY received within PING_WAIT seconds (address conflict detected)
 * @retval 0 No reply received, address available for DHCP offer OR socket creation failed
 * 
 * @note Wait duration controlled by PING_WAIT constant (default 3 seconds in config.h)
 * @note Random ICMP ID (rand16()) prevents confusion with other ping processes
 * @warning Blocks DHCP processing during wait (by design - prevents race conditions)
 * 
 * @see make_icmp_sock() for socket creation
 * @see delay_dhcp() for timeout implementation with DNS/TFTP servicing
 * @see dhcp_reply() in rfc2131.c for caller context
 * 
 * EXAMPLE USAGE:
 * @code
 * // DHCP server before sending OFFER:
 * struct in_addr proposed_ip;
 * proposed_ip.s_addr = htonl(0xC0A80164);  // 192.168.1.100
 * 
 * if (icmp_ping(proposed_ip)) {
 *   // Address in use, try next from pool
 * } else {
 *   // Address available, send DHCPOFFER
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 3.1 paragraph 2: "The server SHOULD probe the reused address
 * before allocating the address, e.g., with an ICMP echo request."
 * 
 * SIDE EFFECTS:
 * - Sends ICMP ECHO_REQUEST packet on network
 * - Blocks for up to PING_WAIT seconds
 * - Services DNS and TFTP requests during wait (via delay_dhcp)
 * - Creates/closes socket on Linux/Solaris
 * - Updates dnsmasq_time() for clock tracking
 * 
 * THREAD SAFETY:
 * Not thread-safe. Uses global daemon->dhcp_icmp_fd on BSD.
 */
int icmp_ping(struct in_addr addr)
{
  /* Try and get an ICMP echo from a machine. */

  int fd;
  struct sockaddr_in saddr;
  struct { 
    struct ip ip;
    struct icmp icmp;
  } packet;
  unsigned short id = rand16();
  unsigned int i, j;
  int gotreply = 0;

#if defined(HAVE_LINUX_NETWORK) || defined (HAVE_SOLARIS_NETWORK)
  if ((fd = make_icmp_sock()) == -1)
    return 0;
#else
  int opt = 2000;
  fd = daemon->dhcp_icmp_fd;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
#endif

  saddr.sin_family = AF_INET;
  saddr.sin_port = 0;
  saddr.sin_addr = addr;
#ifdef HAVE_SOCKADDR_SA_LEN
  saddr.sin_len = sizeof(struct sockaddr_in);
#endif
  
  memset(&packet.icmp, 0, sizeof(packet.icmp));
  packet.icmp.icmp_type = ICMP_ECHO;
  packet.icmp.icmp_id = id;
  for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
    j += ((u16 *)&packet.icmp)[i];
  while (j>>16)
    j = (j & 0xffff) + (j >> 16);  
  packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;
  
  while (retry_send(sendto(fd, (char *)&packet.icmp, sizeof(struct icmp), 0, 
			   (struct sockaddr *)&saddr, sizeof(saddr))));
  
  gotreply = delay_dhcp(dnsmasq_time(), PING_WAIT, fd, addr.s_addr, id);

#if defined(HAVE_LINUX_NETWORK) || defined(HAVE_SOLARIS_NETWORK)
  close(fd);
#else
  opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
#endif

  return gotreply;
}

/**
 * @brief Delay DHCP processing while waiting for ICMP reply or timeout
 * 
 * @detailed
 * Implements timed wait for ICMP ECHO_REPLY during ping-before-offer address testing. Loops for
 * specified duration (typically PING_WAIT=3 seconds) while servicing DNS and TFTP requests but
 * ignoring DHCP packets and signals. Returns early (1) if ICMP reply from target address received,
 * or after timeout (0). Uses poll() with 250ms timeout to avoid dnsmasq_time() non-monotonic clock
 * issues. Timeout counted via iteration fallback (sec * 4 quarter-second polls).
 * 
 * While waiting: (1) Polls ICMP socket (fd != -1) for ECHO_REPLY, (2) polls DNS listeners via
 * set_dns_listeners(), (3) polls TFTP listeners if HAVE_TFTP, (4) dispatches ready sockets,
 * (5) ignores DHCP listeners to prevent re-entrancy. Clock skew protection: timeout_count fallback
 * prevents infinite loop if system time adjusted backward.
 * 
 * @param start Wait start time from dnsmasq_time() (reference timestamp)
 * @param sec Duration to wait in seconds (typically PING_WAIT=3)
 * @param fd ICMP socket file descriptor to monitor, or -1 for timeout-only wait
 * @param addr Expected source IPv4 address (host byte order) for ICMP reply filtering
 * @param id Expected ICMP ID in ECHO_REPLY for matching specific ping
 * 
 * @return 1 if ICMP reply matched, 0 on timeout or no match
 * 
 * @retval 1 ICMP ECHO_REPLY received from addr with matching id before timeout
 * @retval 0 Timeout reached without matching reply, or fd == -1 (timeout-only mode)
 * 
 * @note DNS and TFTP requests serviced during wait (dnsmasq remains responsive)
 * @note DHCP requests deliberately ignored during wait (prevents re-entrant address checks)
 * @note Signals not processed during wait (deferred until wait completes)
 * @warning Blocks DHCP processing for up to sec seconds (typically 3s)
 * 
 * @see icmp_ping() for caller context
 * @see check_dns_listeners() for DNS processing during wait
 * @see poll_listen() for file descriptor monitoring
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from icmp_ping() after sending ECHO_REQUEST:
 * int gotreply = delay_dhcp(dnsmasq_time(), PING_WAIT, icmp_fd, 
 *                           addr.s_addr, icmp_id);
 * if (gotreply) {
 *   // Address in use, conflict detected
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Supports RFC 2131 Section 3.1 ping-before-offer mechanism.
 * 
 * SIDE EFFECTS:
 * - Blocks for up to sec seconds
 * - Services DNS and TFTP during wait (modifies global state)
 * - Ignores DHCP and signals during wait
 * - Advances dnsmasq_time() clock
 * - Timeout fallback protects against system clock adjustments
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies global event processing state.
 */
int delay_dhcp(time_t start, int sec, int fd, uint32_t addr, unsigned short id)
{
  /* Delay processing DHCP packets for "sec" seconds counting from "start".
     If "fd" is not -1 it will stop waiting if an ICMP echo reply is received
     from "addr" with ICMP ID "id" and return 1 */

  /* Note that whilst waiting, we check for
     (and service) events on the DNS and TFTP  sockets, (so doing that
     better not use any resources our caller has in use...)
     but we remain deaf to signals or further DHCP packets. */

  /* There can be a problem using dnsmasq_time() to end the loop, since
     it's not monotonic, and can go backwards if the system clock is
     tweaked, leading to the code getting stuck in this loop and
     ignoring DHCP requests. To fix this, we check to see if select returned
     as a result of a timeout rather than a socket becoming available. We
     only allow this to happen as many times as it takes to get to the wait time
     in quarter-second chunks. This provides a fallback way to end loop. */

  int rc, timeout_count;
  time_t now;

  for (now = dnsmasq_time(), timeout_count = 0;
       (difftime(now, start) <= (float)sec) && (timeout_count < sec * 4);)
    {
      poll_reset();
      if (fd != -1)
        poll_listen(fd, POLLIN);
      set_dns_listeners();
      set_log_writer();
      
#ifdef HAVE_DHCP6
      if (daemon->doing_ra)
	poll_listen(daemon->icmp6fd, POLLIN); 
#endif
      
      rc = do_poll(250);
      
      if (rc < 0)
	continue;
      else if (rc == 0)
	timeout_count++;

      now = dnsmasq_time();
      
      check_log_writer(0);
      check_dns_listeners(now);
      
#ifdef HAVE_DHCP6
      if (daemon->doing_ra && poll_check(daemon->icmp6fd, POLLIN))
	icmp6_packet(now);
#endif
      
#ifdef HAVE_TFTP
      check_tftp_listeners(now);
#endif

      if (fd != -1)
        {
          struct {
            struct ip ip;
            struct icmp icmp;
          } packet;
          struct sockaddr_in faddr;
          socklen_t len = sizeof(faddr);
	  
          if (poll_check(fd, POLLIN) &&
	      recvfrom(fd, &packet, sizeof(packet), 0, (struct sockaddr *)&faddr, &len) == sizeof(packet) &&
	      addr == faddr.sin_addr.s_addr &&
	      packet.icmp.icmp_type == ICMP_ECHOREPLY &&
	      packet.icmp.icmp_seq == 0 &&
	      packet.icmp.icmp_id == id)
	    return 1;
	}
    }

  return 0;
}
#endif /* HAVE_DHCP */
