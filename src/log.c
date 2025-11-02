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
 * @file log.c
 * @brief Asynchronous queued logging with syslog integration
 *
 * DETAILED PURPOSE:
 * This module implements non-blocking asynchronous logging to prevent deadlocks
 * between dnsmasq and syslogd. When syslogd makes DNS lookups through dnsmasq and
 * dnsmasq blocks waiting for syslogd to accept log messages, a circular dependency
 * deadlock can occur. This module solves the problem by queueing log messages in
 * memory and writing them asynchronously without blocking the main event loop.
 *
 * The logging system uses a queue of log entries (up to MAX_LOGS messages) that
 * are written opportunistically when the log socket is ready. If the queue fills,
 * messages are dropped and the drop event itself is logged. The implementation
 * handles syslog connection failures gracefully with automatic reconnection attempts
 * and implements backpressure via exponential delays when the queue grows large.
 *
 * The module supports multiple logging destinations: syslog via UNIX domain socket
 * (SOCK_DGRAM or SOCK_STREAM), log files with rotation support (SIGUSR2), stderr
 * for debugging, and Android logcat on Android platforms. Log messages conform to
 * RFC 3164 wire protocol format when sent to syslog.
 *
 * KEY RESPONSIBILITIES:
 * - my_syslog() - Primary logging interface with varargs and priority filtering
 * - log_write() - Asynchronous queue processor that writes messages without blocking
 * - log_reopen() - Handles log file rotation (SIGUSR2) and syslog reconnection
 * - flush_log() - Drains message queue at shutdown
 * - die() - Fatal error handler with guaranteed message delivery
 * - set_log_writer() - Registers log socket with poll() for write readiness
 * - check_log_writer() - Processes queued messages when socket is writable
 * - log_start() - Initializes logging subsystem with proper ownership
 *
 * DEPENDENCIES:
 * - dnsmasq.h - Global daemon structure and option flags
 * - syslog(3) - System logging facility interface
 * - poll(2) - Event notification for non-blocking writes
 * - RFC 3164 - BSD syslog protocol wire format
 *
 * Calling relationships:
 * - Called by: All dnsmasq modules for logging (forward.c, cache.c, dhcp.c, etc.)
 * - Calls: poll_listen(), poll_check() for event loop integration
 * - Calls: openlog(), vsyslog() as fallback on Solaris/Android or when queue disabled
 *
 * DATA STRUCTURES:
 * - struct log_entry (lines 47-52) - Queued log message with payload and metadata
 * - entries - Queue head for messages awaiting transmission
 * - free_entries - Freelist of available log_entry structures for reuse
 *
 * COMPILE-TIME OPTIONS:
 * - MAX_MESSAGE (1024) - Maximum log message size per RFC 3164
 * - LOG_DAEMON - Default syslog facility (overridden by daemon->log_fac)
 * - __ANDROID__ - Enables Android logcat integration instead of syslog
 * - HAVE_SOLARIS_NETWORK - Solaris uses vsyslog() instead of /dev/log socket
 * - HAVE_SOCKADDR_SA_LEN - BSD-style socket address length field
 *
 * THREADING/CONCURRENCY:
 * This module operates in dnsmasq's single-process event-driven model and is
 * NOT thread-safe. All logging calls occur from the main event loop thread.
 * Non-blocking I/O is used to prevent stalls, with messages queued in memory
 * when the log destination is not immediately ready. The queue prevents
 * blocking but introduces asynchronous behavior - log messages may be delayed
 * or dropped under extreme load.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef __ANDROID__
#  include <android/log.h>
#endif

/* Implement logging to /dev/log asynchronously. If syslogd is 
   making DNS lookups through dnsmasq, and dnsmasq blocks awaiting
   syslogd, then the two daemons can deadlock. We get around this
   by not blocking when talking to syslog, instead we queue up to 
   MAX_LOGS messages. If more are queued, they will be dropped,
   and the drop event itself logged. */

/* The "wire" protocol for logging is defined in RFC 3164 */

/* From RFC 3164 */
#define MAX_MESSAGE 1024

/* defaults in case we die() before we log_start() */
static int log_fac = LOG_DAEMON;
static int log_stderr = 0;
static int echo_stderr = 0;
static int log_fd = -1;
static int log_to_file = 0;
static int entries_alloced = 0;
static int entries_lost = 0;
static int connection_good = 1;
static int max_logs = 0;
static int connection_type = SOCK_DGRAM;

/**
 * @struct log_entry
 * @brief Queued log message entry with RFC 3164 formatted payload
 *
 * Represents a single log message in the asynchronous queue. Each entry contains
 * a partially or fully formatted log message according to RFC 3164 syslog protocol,
 * along with metadata to handle partial writes and detect stale entries after fork().
 *
 * LIFECYCLE:
 * - Allocation: Allocated from free_entries freelist or via malloc() if under max_logs limit
 * - Initialization: Populated by my_syslog() with formatted message and metadata
 * - Usage: Consumed by log_write() which may perform multiple partial writes
 * - Deallocation: Returned to free_entries freelist by free_entry() for reuse
 *
 * MEMORY LAYOUT:
 * Structure size is approximately 1KB (MAX_MESSAGE=1024 + metadata overhead).
 * The payload contains the complete formatted log message including syslog priority,
 * timestamp, process name, and actual log text. The offset and length fields enable
 * resumption of partial writes when the log socket blocks.
 *
 * USAGE PATTERNS:
 * - Entries form a singly-linked queue (entries list) processed FIFO
 * - Free entries are maintained in freelist (free_entries) for efficient reuse
 * - Maximum queue depth controlled by max_logs to prevent unbounded memory growth
 * - Entries from prior to fork() are detected and discarded via pid comparison
 *
 * @var log_entry::offset
 * Current write position within payload for partial write resumption (0 = not started)
 *
 * @var log_entry::length
 * Total length of formatted message including terminating zero (decremented as written)
 *
 * @var log_entry::pid
 * Process ID that created this entry, used to detect and discard stale entries after fork()
 *
 * @var log_entry::next
 * Next entry in queue (entries list) or freelist (free_entries), NULL if last
 *
 * @var log_entry::payload
 * RFC 3164 formatted log message: "<priority>timestamp hostname tag: message\0"
 */
struct log_entry {
  int offset, length;
  pid_t pid; /* to avoid duplicates over a fork */
  struct log_entry *next;
  char payload[MAX_MESSAGE];
};

static struct log_entry *entries = NULL;
static struct log_entry *free_entries = NULL;

/**
 * @brief Initialize logging subsystem and open log destination
 *
 * @detailed
 * Performs complete logging system initialization during dnsmasq startup. Configures
 * the logging facility based on daemon options (syslog, file, stderr), sets up file
 * ownership for log rotation compatibility, and pre-allocates the message queue if
 * queuing is enabled. If logging to a file owned by root and privilege dropping is
 * configured, changes ownership to the target user to enable log rotation tools to
 * preserve ownership. Handles both queued (asynchronous) and non-queued (synchronous)
 * logging modes based on daemon->max_logs setting.
 *
 * @param[in] ent_pw Password database entry for target user when dropping privileges,
 *                   NULL if running as unprivileged user or not dropping privileges
 * @param[in] errfd File descriptor for sending startup error events to parent process
 *                  (used if log_reopen() fails to report EVENT_LOG_ERR)
 *
 * @return 0 on success, errno value if fchown() failed (non-fatal, warning only)
 *
 * @retval 0 Logging initialized successfully
 * @retval EPERM fchown() failed due to insufficient permissions (non-fatal)
 * @retval ENOENT fchown() failed because file descriptor invalid (non-fatal)
 *
 * @note This function calls _exit(0) if log_reopen() fails, terminating the process.
 *       The caller will not receive control in this failure case.
 *
 * @warning Must be called early in daemon initialization, after option parsing but
 *          before privilege dropping. Modifies global logging state (log_fac, log_fd,
 *          max_logs, echo_stderr). Not safe to call multiple times.
 *
 * @see log_reopen() for actual log file/socket opening
 * @see flush_log() for shutdown cleanup
 *
 * EXAMPLE USAGE:
 * @code
 * struct passwd *target_user = getpwnam("dnsmasq");
 * int startup_pipe[2];
 * pipe(startup_pipe);
 * int chown_error = log_start(target_user, startup_pipe[1]);
 * if (chown_error != 0)
 *   my_syslog(LOG_WARNING, "Could not change log file ownership: %s", strerror(chown_error));
 * @endcode
 *
 * SIDE EFFECTS:
 * - Opens log file descriptor (log_fd) via log_reopen()
 * - Allocates memory for message queue if max_logs > 0
 * - May change log file ownership and permissions via fchown()/fchmod()
 * - Calls _exit(0) and terminates process if log_reopen() fails
 * - Sets global logging configuration (log_fac, echo_stderr, log_to_file, max_logs)
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies multiple global variables. Must be called only once
 * from main thread during daemon initialization, before any logging calls.
 */
int log_start(struct passwd *ent_pw, int errfd)
{
  int ret = 0;

  echo_stderr = option_bool(OPT_DEBUG);

  if (daemon->log_fac != -1)
    log_fac = daemon->log_fac;
#ifdef LOG_LOCAL0
  else if (option_bool(OPT_DEBUG))
    log_fac = LOG_LOCAL0;
#endif

  if (daemon->log_file)
    { 
      log_to_file = 1;
      daemon->max_logs = 0;
      if (strcmp(daemon->log_file, "-") == 0)
	{
	  log_stderr = 1;
	  echo_stderr = 0;
	  log_fd = dup(STDERR_FILENO);
	}
    }
  
  max_logs = daemon->max_logs;

  if (!log_reopen(daemon->log_file))
    {
      send_event(errfd, EVENT_LOG_ERR, errno, daemon->log_file ? daemon->log_file : "");
      _exit(0);
    }

  /* if queuing is inhibited, make sure we allocate
     the one required buffer now. */
  if (max_logs == 0)
    {  
      free_entries = safe_malloc(sizeof(struct log_entry));
      free_entries->next = NULL;
      entries_alloced = 1;
    }

  /* If we're running as root and going to change uid later,
     change the ownership here so that the file is always owned by
     the dnsmasq user. Then logrotate can just copy the owner.
     Failure of the chown call is OK, (for instance when started as non-root).
     
     If we've created a file with group-id root, we also make
     the file group-writable. This gives processes in the root group
     write access to the file and avoids the problem that on some systems,
     once the file is owned by the dnsmasq user, it can't be written
     whilst dnsmasq is running as root during startup.
 */
  if (log_to_file && !log_stderr && ent_pw && ent_pw->pw_uid != 0)
    {
      struct stat ls;
      if (getgid() == 0 && fstat(log_fd, &ls) == 0 && ls.st_gid == 0 &&
	  (ls.st_mode & S_IWGRP) == 0)
	(void)fchmod(log_fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
      if (fchown(log_fd, ent_pw->pw_uid, -1) != 0)
	ret = errno;
    }

  return ret;
}

/**
 * @brief Reopen log destination for rotation or reconnection
 *
 * @detailed
 * Closes the current log file descriptor and opens a new one, either to a named
 * file or to the syslog UNIX domain socket (/dev/log). Used for log file rotation
 * triggered by SIGUSR2, and for automatic reconnection when the syslog socket
 * connection is lost. For syslog connections, attempts to open with non-blocking
 * mode if message queueing is enabled (max_logs > 0) to prevent blocking the event
 * loop. Handles platform differences - on Solaris and Android, syslog logging uses
 * vsyslog() system call instead of socket communication.
 *
 * @param[in] log_file Path to log file to open, or NULL to open syslog socket
 *                     (typically /dev/log on Unix, ignored on Solaris/Android)
 *
 * @return Boolean success indicator
 *
 * @retval 1 Log destination opened successfully, log_fd is valid
 * @retval 0 Failed to open log destination, log_fd is -1
 *
 * @note On Solaris and Android platforms, always returns 1 when log_file is NULL
 *       because these platforms use vsyslog() instead of socket-based logging.
 *       The log_fd remains -1 to signal vsyslog() fallback in my_syslog().
 *
 * @warning If reopening syslog socket and max_logs is 0, the socket is left in
 *          blocking mode. This can cause event loop stalls if syslogd is slow.
 *          Set max_logs > 0 to enable non-blocking mode.
 *
 * @see log_start() for initial log system setup
 * @see log_write() for connection error handling and automatic reconnection
 *
 * EXAMPLE USAGE:
 * @code
 * // Log file rotation triggered by SIGUSR2 signal handler
 * if (got_sigusr2) {
 *   if (!log_reopen(daemon->log_file))
 *     my_syslog(LOG_ERR, "Failed to reopen log file: %s", strerror(errno));
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Closes existing log_fd if open
 * - Opens new file descriptor for log file or syslog socket
 * - Sets O_NONBLOCK flag on socket if max_logs > 0
 * - May change connection_type between SOCK_DGRAM and SOCK_STREAM (see log_write)
 * - Creates log file with permissions 0640 (owner read/write, group read) if missing
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global log_fd. Must be called only from main event
 * loop thread, never from signal handlers except via async-signal-safe queuing.
 */
int log_reopen(char *log_file)
{
  if (!log_stderr)
    {      
      if (log_fd != -1)
	close(log_fd);
      
      /* NOTE: umask is set to 022 by the time this gets called */
      
      if (log_file)
	log_fd = open(log_file, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP);
      else
	{
#if defined(HAVE_SOLARIS_NETWORK) || defined(__ANDROID__)
	  /* Solaris logging is "different", /dev/log is not unix-domain socket.
	     Just leave log_fd == -1 and use the vsyslog call for everything.... */
#   define _PATH_LOG ""  /* dummy */
	  return 1;
#else
	  int flags;
	  log_fd = socket(AF_UNIX, connection_type, 0);
	  
	  /* if max_logs is zero, leave the socket blocking */
	  if (log_fd != -1 && max_logs != 0 && (flags = fcntl(log_fd, F_GETFL)) != -1)
	    fcntl(log_fd, F_SETFL, flags | O_NONBLOCK);
#endif
	}
    }
  
  return log_fd != -1;
}

/**
 * @brief Return consumed log entry to freelist for reuse
 *
 * @detailed
 * Removes the head entry from the active message queue (entries list) and returns
 * it to the freelist (free_entries) for memory reuse. This maintains a pool of
 * pre-allocated log_entry structures to avoid malloc/free overhead during normal
 * operation. Called by log_write() after successfully transmitting a complete
 * message. The freelist pattern reduces memory fragmentation and improves performance
 * during high-volume logging scenarios.
 *
 * @note Assumes entries list is non-empty (caller must verify entries != NULL).
 *       Does not perform NULL checking - will dereference NULL if called incorrectly.
 *
 * @warning Not safe to call when entries is NULL - will cause segmentation fault.
 *          Caller (log_write) is responsible for checking queue non-empty before calling.
 *
 * @see my_syslog() for entry allocation from freelist
 * @see log_write() for entry consumption and freelist return
 *
 * EXAMPLE USAGE:
 * @code
 * // Internal usage within log_write() after successful message transmission
 * if (entries && entries->length == 0) {
 *   free_entry();  // Return completed entry to freelist
 *   if (entries_lost != 0) {
 *     my_syslog(LOG_WARNING, "overflow: %d log entries lost", entries_lost);
 *   }
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies entries global pointer to point to next queued message (or NULL)
 * - Adds freed entry to head of free_entries freelist
 * - Does not free memory - maintains pre-allocated pool for reuse
 *
 * THREAD SAFETY:
 * Not thread-safe. Manipulates global queue pointers. Must be called only from
 * main event loop thread during log_write() processing.
 */
static void free_entry(void)
{
  struct log_entry *tmp = entries;
  entries = tmp->next;
  tmp->next = free_entries;
  free_entries = tmp;
}

/**
 * @brief Write queued log messages asynchronously without blocking
 *
 * @detailed
 * Processes the log message queue (entries list) by writing messages to log_fd
 * without blocking. Handles partial writes by maintaining offset/length state
 * in each entry, allowing interrupted writes to resume. Implements sophisticated
 * error handling including automatic reconnection for lost syslog connections,
 * protocol fallback between SOCK_DGRAM and SOCK_STREAM, and graceful degradation
 * to vsyslog() if socket operations fail persistently. Detects and discards stale
 * entries created before fork() by comparing PIDs. Returns immediately on EAGAIN/
 * EWOULDBLOCK to avoid blocking the event loop.
 *
 * @note Called opportunistically: by my_syslog() after queuing, by check_log_writer()
 *       when poll() indicates socket writable, and by flush_log() at shutdown.
 *
 * @warning For file logging, converts zero terminator to newline. For datagram sockets,
 *          omits zero terminator. For stream sockets, includes zero as record terminator.
 *          Protocol differences are handled automatically based on connection_type.
 *
 * @see my_syslog() for message queuing and initial write attempt
 * @see set_log_writer() for poll() registration when queue non-empty
 * @see check_log_writer() for write processing when socket ready
 *
 * EXAMPLE USAGE:
 * @code
 * // Typical internal usage - called automatically by logging infrastructure
 * my_syslog(LOG_INFO, "DNS query from %s", client_addr);  // Calls log_write() internally
 * 
 * // Event loop integration
 * if (poll_check(log_fd, POLLOUT))
 *   log_write();  // Process queue when socket becomes writable
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 3164 BSD syslog protocol wire format. Messages formatted as:
 * "<priority>timestamp hostname tag[pid]: message" for syslog destinations.
 * Priority field contains facility and severity encoded per RFC 3164 Section 4.1.
 *
 * SIDE EFFECTS:
 * - Writes data to log_fd (file or socket)
 * - Modifies entries list by consuming completed messages via free_entry()
 * - May close and reopen log_fd on connection errors (calls log_reopen)
 * - May change connection_type between SOCK_DGRAM and SOCK_STREAM on EPROTOTYPE
 * - Recursively calls my_syslog() to report dropped messages (entries_lost)
 * - Sets connection_good = 0 on persistent connection failures
 * - Falls back to vsyslog() by setting log_fd = -1 on unrecoverable errors
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global queue state (entries, free_entries, connection_good).
 * Must be called only from main event loop thread. The recursive my_syslog() call
 * for reporting dropped messages is safe because entries_lost is zeroed before call,
 * preventing infinite recursion.
 */
static void log_write(void)
{
  ssize_t rc;
   
  while (entries)
    {
      /* The data in the payload is written with a terminating zero character 
	 and the length reflects this. For a stream connection we need to 
	 send the zero as a record terminator, but this isn't done for a 
	 datagram connection, so treat the length as one less than reality 
	 to elide the zero. If we're logging to a file, turn the zero into 
	 a newline, and leave the length alone. */
      int len_adjust = 0;

      if (log_to_file)
	entries->payload[entries->offset + entries->length - 1] = '\n';
      else if (connection_type == SOCK_DGRAM)
	len_adjust = 1;

      /* Avoid duplicates over a fork() */
      if (entries->pid != getpid())
	{
	  free_entry();
	  continue;
	}

      connection_good = 1;

      if ((rc = write(log_fd, entries->payload + entries->offset, entries->length - len_adjust)) != -1)
	{
	  entries->length -= rc;
	  entries->offset += rc;
	  if (entries->length == len_adjust)
	    {
	      free_entry();
	      if (entries_lost != 0)
		{
		  int e = entries_lost;
		  entries_lost = 0; /* avoid wild recursion */
		  my_syslog(LOG_WARNING, _("overflow: %d log entries lost"), e);
		}	  
	    }
	  continue;
	}
      
      if (errno == EINTR)
	continue;

      if (errno == EAGAIN || errno == EWOULDBLOCK)
	return; /* syslogd busy, go again when select() or poll() says so */
      
      if (errno == ENOBUFS)
	{
	  connection_good = 0;
	  return;
	}

      /* errors handling after this assumes sockets */ 
      if (!log_to_file)
	{
	  /* Once a stream socket hits EPIPE, we have to close and re-open
	     (we ignore SIGPIPE) */
	  if (errno == EPIPE)
	    {
	      if (log_reopen(NULL))
		continue;
	    }
	  else if (errno == ECONNREFUSED || 
		   errno == ENOTCONN || 
		   errno == EDESTADDRREQ || 
		   errno == ECONNRESET)
	    {
	      /* socket went (syslogd down?), try and reconnect. If we fail,
		 stop trying until the next call to my_syslog() 
		 ECONNREFUSED -> connection went down
		 ENOTCONN -> nobody listening
		 (ECONNRESET, EDESTADDRREQ are *BSD equivalents) */
	      
	      struct sockaddr_un logaddr;
	      
#ifdef HAVE_SOCKADDR_SA_LEN
	      logaddr.sun_len = sizeof(logaddr) - sizeof(logaddr.sun_path) + strlen(_PATH_LOG) + 1; 
#endif
	      logaddr.sun_family = AF_UNIX;
	      safe_strncpy(logaddr.sun_path, _PATH_LOG, sizeof(logaddr.sun_path));
	      
	      /* Got connection back? try again. */
	      if (connect(log_fd, (struct sockaddr *)&logaddr, sizeof(logaddr)) != -1)
		continue;
	      
	      /* errors from connect which mean we should keep trying */
	      if (errno == ENOENT || 
		  errno == EALREADY || 
		  errno == ECONNREFUSED ||
		  errno == EISCONN || 
		  errno == EINTR ||
		  errno == EAGAIN || 
		  errno == EWOULDBLOCK)
		{
		  /* try again on next syslog() call */
		  connection_good = 0;
		  return;
		}
	      
	      /* try the other sort of socket... */
	      if (errno == EPROTOTYPE)
		{
		  connection_type = connection_type == SOCK_DGRAM ? SOCK_STREAM : SOCK_DGRAM;
		  if (log_reopen(NULL))
		    continue;
		}
	    }
	}

      /* give up - fall back to syslog() - this handles out-of-space
	 when logging to a file, for instance. */
      log_fd = -1;
      my_syslog(LOG_CRIT, _("log failed: %s"), strerror(errno));
      return;
    }
}

/**
 * @brief Primary logging interface with priority filtering and asynchronous queueing
 *
 * @detailed
 * Main entry point for all dnsmasq logging. Formats messages using printf-style varargs,
 * applies priority-based filtering, adds service-specific tags (tftp/dhcp/script/debug),
 * and queues messages for asynchronous transmission. Supports multiple logging backends:
 * stderr for debugging (--debug), syslog via UNIX domain socket, log files with rotation,
 * and Android logcat. Implements queue management with exponential backpressure delays
 * to prevent cache-dump-style operations from overwhelming the log queue. Falls back to
 * synchronous vsyslog() if log_fd is -1 (Solaris/Android or initialization failures).
 *
 * @param[in] priority Syslog priority level (LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING,
 *                     LOG_ERR, LOG_CRIT) from sys/syslog.h, optionally OR'd with service
 *                     flags (MS_TFTP, MS_DHCP, MS_SCRIPT, MS_DEBUG) for log separation.
 *                     MS_DEBUG messages are suppressed unless OPT_LOG_DEBUG is enabled.
 * @param[in] format Printf-style format string for log message, followed by varargs
 * @param[in] ... Variable arguments matching format string specifiers
 *
 * @note Priority facility bits (MS_TFTP, MS_DHCP, MS_SCRIPT, MS_DEBUG) are extracted
 *       and used for service tagging (e.g., "dnsmasq-tftp"), then stripped via LOG_PRI()
 *       macro to obtain actual syslog priority level (severity).
 *
 * @note Messages are queued in memory (up to max_logs entries). If queue is full,
 *       new messages are dropped and entries_lost counter incremented. When queue
 *       space becomes available, a summary message reports total dropped count.
 *
 * @warning Asynchronous logging means messages may not be written immediately. Under
 *          extreme load with full queue, messages can be lost. The queue depth (max_logs)
 *          trades memory usage against message loss probability. Set max_logs=0 to
 *          disable queueing for synchronous but potentially blocking behavior.
 *
 * @warning Recursive calls are possible when reporting dropped messages (entries_lost).
 *          This is safe because entries_lost is zeroed before the recursive call,
 *          preventing infinite recursion.
 *
 * @see log_write() for asynchronous queue processing
 * @see set_log_writer() for poll() integration enabling write notification
 * @see log_start() for logging subsystem initialization
 *
 * EXAMPLE USAGE:
 * @code
 * // Basic DNS logging
 * my_syslog(LOG_INFO, "query[A] example.com from %s", inet_ntoa(client_addr));
 * 
 * // DHCP-specific logging with service tag
 * my_syslog(LOG_INFO | MS_DHCP, "DHCPACK(eth0) %s %s", mac_addr, ip_addr);
 * 
 * // Debug logging (suppressed unless --log-debug option set)
 * my_syslog(LOG_DEBUG | MS_DEBUG, "cache entry expired for %s", domain);
 * 
 * // Error logging with automatic errno expansion
 * my_syslog(LOG_ERR, "failed to bind socket: %s", strerror(errno));
 * @endcode
 *
 * RFC COMPLIANCE:
 * Priority encoding follows RFC 3164 Section 4.1: priority = facility * 8 + severity.
 * Message format conforms to RFC 3164 BSD syslog protocol wire format with timestamp,
 * hostname, tag, and message fields. Maximum message size limited to MAX_MESSAGE (1024
 * bytes) per RFC 3164 Section 4.1 recommendation.
 *
 * SIDE EFFECTS:
 * - Allocates log_entry from freelist or via malloc() if queue not full
 * - Appends entry to global entries queue for asynchronous transmission
 * - Increments entries_lost if queue is full (message dropped)
 * - Calls log_write() to attempt immediate transmission if socket available
 * - May call nanosleep() for exponential backpressure delay if queue depth > 8
 * - Writes to stderr if echo_stderr enabled (--debug mode)
 * - Falls back to vsyslog() if log_fd is -1 (also writes to Android logcat on Android)
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global queue state (entries, free_entries, entries_alloced,
 * entries_lost). Must be called only from main event loop thread. The varargs handling
 * via va_list is reentrant-safe but queue manipulation is not.
 */
void my_syslog(int priority, const char *format, ...)
{
  va_list ap;
  struct log_entry *entry;
  time_t time_now;
  char *p;
  size_t len;
  pid_t pid = getpid();
  char *func = "";

  if ((LOG_FACMASK & priority) == MS_TFTP)
    func = "-tftp";
  else if ((LOG_FACMASK & priority) == MS_DHCP)
    func = "-dhcp";
  else if ((LOG_FACMASK & priority) == MS_SCRIPT)
    func = "-script";
  else if ((LOG_FACMASK & priority) == MS_DEBUG)
    {
      if (!option_bool(OPT_LOG_DEBUG))
	return;
      func = "-debug";
    }
  
#ifdef LOG_PRI
  priority = LOG_PRI(priority);
#else
  /* Solaris doesn't have LOG_PRI */
  priority &= LOG_PRIMASK;
#endif

  if (echo_stderr) 
    {
      fprintf(stderr, "dnsmasq%s: ", func);
      va_start(ap, format);
      vfprintf(stderr, format, ap);
      va_end(ap);
      fputc('\n', stderr);
    }

  if (log_fd == -1)
    {
#ifdef __ANDROID__
      /* do android-specific logging. 
	 log_fd is always -1 on Android except when logging to a file. */
      int alog_lvl;
      
      if (priority <= LOG_ERR)
	alog_lvl = ANDROID_LOG_ERROR;
      else if (priority == LOG_WARNING)
	alog_lvl = ANDROID_LOG_WARN;
      else if (priority <= LOG_INFO)
	alog_lvl = ANDROID_LOG_INFO;
      else
	alog_lvl = ANDROID_LOG_DEBUG;

      va_start(ap, format);
      __android_log_vprint(alog_lvl, "dnsmasq", format, ap);
      va_end(ap);
#else
      /* fall-back to syslog if we die during startup or 
	 fail during running (always on Solaris). */
      static int isopen = 0;

      if (!isopen)
	{
	  openlog("dnsmasq", LOG_PID, log_fac);
	  isopen = 1;
	}
      va_start(ap, format);  
      vsyslog(priority, format, ap);
      va_end(ap);
#endif

      return;
    }
  
  if ((entry = free_entries))
    free_entries = entry->next;
  else if (entries_alloced < max_logs && (entry = malloc(sizeof(struct log_entry))))
    entries_alloced++;
  
  if (!entry)
    entries_lost++;
  else
    {
      /* add to end of list, consumed from the start */
      entry->next = NULL;
      if (!entries)
	entries = entry;
      else
	{
	  struct log_entry *tmp;
	  for (tmp = entries; tmp->next; tmp = tmp->next);
	  tmp->next = entry;
	}
      
      time(&time_now);
      p = entry->payload;
      if (!log_to_file)
	p += sprintf(p, "<%d>", priority | log_fac);

      /* Omit timestamp for default daemontools situation */
      if (!log_stderr || !option_bool(OPT_NO_FORK)) 
	p += sprintf(p, "%.15s ", ctime(&time_now) + 4);
      
      p += sprintf(p, "dnsmasq%s[%d]: ", func, (int)pid);
        
      len = p - entry->payload;
      va_start(ap, format);  
      len += vsnprintf(p, MAX_MESSAGE - len, format, ap) + 1; /* include zero-terminator */
      va_end(ap);
      entry->length = len > MAX_MESSAGE ? MAX_MESSAGE : len;
      entry->offset = 0;
      entry->pid = pid;
    }
  
  /* almost always, logging won't block, so try and write this now,
     to save collecting too many log messages during a select loop. */
  log_write();
  
  /* Since we're doing things asynchronously, a cache-dump, for instance,
     can now generate log lines very fast. With a small buffer (desirable),
     that means it can overflow the log-buffer very quickly,
     so that the cache dump becomes mainly a count of how many lines 
     overflowed. To avoid this, we delay here, the delay is controlled 
     by queue-occupancy, and grows exponentially. The delay is limited to (2^8)ms.
     The scaling stuff ensures that when the queue is bigger than 8, the delay
     only occurs for the last 8 entries. Once the queue is full, we stop delaying
     to preserve performance.
  */

  if (entries && max_logs != 0)
    {
      int d;
      
      for (d = 0,entry = entries; entry; entry = entry->next, d++);
      
      if (d == max_logs)
	d = 0;
      else if (max_logs > 8)
	d -= max_logs - 8;

      if (d > 0)
	{
	  struct timespec waiter;
	  waiter.tv_sec = 0;
	  waiter.tv_nsec = 1000000 << (d - 1); /* 1 ms */
	  nanosleep(&waiter, NULL);
      
	  /* Have another go now */
	  log_write();
	}
    } 
}

/**
 * @brief Register log socket with poll() for write readiness notification
 *
 * @detailed
 * Conditionally registers the log file descriptor (log_fd) with the event loop's
 * poll() mechanism to receive POLLOUT notifications when the socket becomes writable.
 * Only registers if there are queued messages (entries != NULL) and the connection
 * is believed to be good (connection_good == 1). This enables the event loop to
 * opportunistically process the log queue when the log destination is ready to
 * accept data, avoiding busy-waiting or blocking. Called from main event loop
 * setup code before each poll() invocation.
 *
 * @note Does nothing if log_fd is -1 (logging to vsyslog), entries is NULL (queue empty),
 *       or connection_good is 0 (known bad connection state). These conditions indicate
 *       no work to be done or connection repair needed on next my_syslog() call.
 *
 * @warning Must be called during poll() setup phase before blocking in poll() syscall.
 *          Not safe to call from signal handlers - event loop integration only.
 *
 * @see poll_listen() for event registration mechanism
 * @see check_log_writer() for event processing when POLLOUT received
 * @see log_write() for queue processing logic
 *
 * EXAMPLE USAGE:
 * @code
 * // Event loop integration in main daemon loop
 * while (1) {
 *   set_log_writer();  // Register log socket if queue non-empty
 *   // ... register other event sources ...
 *   poll(fds, nfds, timeout);
 *   check_log_writer(0);  // Process log queue if POLLOUT received
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Registers log_fd for POLLOUT events via poll_listen() if conditions met
 * - No side effects if preconditions (queue non-empty, connection good) not met
 *
 * THREAD SAFETY:
 * Not thread-safe. Reads global state (entries, log_fd, connection_good). Must be
 * called only from main event loop thread as part of poll() setup sequence.
 */
void set_log_writer(void)
{
  if (entries && log_fd != -1 && connection_good)
    poll_listen(log_fd, POLLOUT);
}

/**
 * @brief Process queued log messages when socket is writable or on demand
 *
 * @detailed
 * Invokes log_write() to process the message queue if either forced or if poll()
 * indicates the log socket is ready for writing (POLLOUT event received). Called
 * from the event loop after poll() returns to opportunistically drain the queue
 * when the log destination is not blocking. The force parameter allows unconditional
 * queue processing for shutdown scenarios where event notification is bypassed.
 * Validates log_fd is open before checking poll status or processing queue.
 *
 * @param[in] force If non-zero, call log_write() unconditionally without checking
 *                  poll() status. If zero, only call log_write() if POLLOUT event
 *                  received. Used for forced queue drain during shutdown (flush_log).
 *
 * @note Does nothing if log_fd is -1 (vsyslog fallback mode, no queue to process).
 *       The poll_check() call only returns true if POLLOUT was previously registered
 *       via set_log_writer() and poll() detected socket writability.
 *
 * @warning Do not call with force=1 in normal event loop operation as it bypasses
 *          poll() and may cause blocking on slow log destinations. Reserve force=1
 *          for shutdown paths where blocking is acceptable.
 *
 * @see set_log_writer() for POLLOUT event registration
 * @see poll_check() for event status query
 * @see log_write() for queue processing implementation
 *
 * EXAMPLE USAGE:
 * @code
 * // Event loop integration - process queue when socket ready
 * if (poll(fds, nfds, timeout) > 0) {
 *   check_log_writer(0);  // Process if POLLOUT received
 *   // ... process other events ...
 * }
 * 
 * // Forced processing during shutdown
 * check_log_writer(1);  // Drain queue regardless of poll status
 * @endcode
 *
 * SIDE EFFECTS:
 * - Calls log_write() which may write to log_fd, modify queue, reconnect socket
 * - poll_check() consumes the POLLOUT event status for log_fd
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main event loop thread after poll()
 * returns or during controlled shutdown sequence.
 */
void check_log_writer(int force)
{
  if (log_fd != -1 && (force || poll_check(log_fd, POLLOUT)))
    log_write();
}

/**
 * @brief Drain message queue at shutdown ensuring all logs are written
 *
 * @detailed
 * Attempts to write all queued log messages before daemon shutdown, repeatedly
 * calling log_write() with small delays until the queue is empty or the connection
 * is lost. Provides best-effort delivery guarantee - if syslog connection is broken,
 * will abandon remaining messages after detecting connection_good == 0 to avoid
 * hanging shutdown. Closes log_fd after queue draining completes or fails. This
 * ensures critical shutdown messages are not lost and log file descriptors are
 * properly closed before process termination.
 *
 * @note Blocks in 1ms nanosleep() loop between write attempts. Maximum delay is
 *       bounded by queue depth and write success rate, but connection failures
 *       cause immediate exit to prevent indefinite blocking. Acceptable during
 *       shutdown when blocking is tolerable.
 *
 * @warning Will close log_fd even if queue is not fully drained (connection failure
 *          case). Remaining messages in queue will be lost. This tradeoff prevents
 *          hanging on broken syslog connections during shutdown.
 *
 * @see log_write() for queue processing
 * @see die() for fatal error shutdown that calls flush_log()
 *
 * EXAMPLE USAGE:
 * @code
 * // Normal daemon shutdown sequence
 * my_syslog(LOG_INFO, "dnsmasq exiting");
 * flush_log();  // Ensure shutdown message written before exit
 * exit(0);
 * 
 * // Fatal error shutdown (via die() which calls flush_log internally)
 * die("Cannot bind socket: %s", NULL, 1);  // Logs error, flushes, exits
 * @endcode
 *
 * SIDE EFFECTS:
 * - Repeatedly calls log_write() which may write to log_fd and modify queue
 * - Calls nanosleep() for 1ms delays between write attempts (may accumulate)
 * - Closes log_fd via close() when queue empty or connection lost
 * - Sets global state indicating log system shutdown (log_fd becomes closed)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main thread during controlled shutdown.
 * Modifies global log_fd and queue state. Not safe to call while my_syslog() might
 * be called from other contexts (should only be used during single-threaded shutdown).
 */
void flush_log(void)
{
  /* write until queue empty, but don't loop forever if there's
   no connection to the syslog in existence */
  while (log_fd != -1)
    {
      struct timespec waiter;
      log_write();
      if (!entries || !connection_good)
	{
	  close(log_fd);	
	  break;
	}
      waiter.tv_sec = 0;
      waiter.tv_nsec = 1000000; /* 1 ms */
      nanosleep(&waiter, NULL);
    }
}

/**
 * @brief Terminate daemon with fatal error logging and guaranteed message delivery
 *
 * @detailed
 * Handles fatal errors requiring immediate daemon termination. Logs the error message
 * with automatic errno expansion, ensures the message is written both to configured
 * log destination and to stderr for visibility, flushes all queued messages to prevent
 * loss of diagnostic information, and terminates the process with specified exit code.
 * Used for unrecoverable startup errors (bind failures, configuration errors) and
 * runtime failures requiring shutdown (resource exhaustion, privilege drop failures).
 * The dual logging (log + stderr) ensures error visibility even if logging is misconfigured.
 *
 * @param[in] message Printf-style format string for error message, typically with two
 *                    %s placeholders. First %s replaced with arg1, second with strerror(errno)
 *                    if arg1 is NULL, otherwise second %s replaced with strerror(errno).
 * @param[in] arg1 First argument for message format string, or NULL to use strerror(errno)
 *                 as first argument. Provides context like filename, address, etc.
 * @param[in] exit_code Exit status code for process termination (passed to exit() syscall)
 *
 * @note This function never returns - it terminates the process via exit() after logging.
 *       Caller should not have cleanup code after die() call as it will not execute.
 *
 * @note Temporarily enables echo_stderr to ensure error appears on stderr even if not
 *       normally configured, then disables it for the "FAILED to start up" message to
 *       avoid duplication in log-to-stderr mode.
 *
 * @warning This is a fatal error handler - terminates the process unconditionally.
 *          Do not use for recoverable errors. Use my_syslog(LOG_ERR, ...) for non-fatal errors.
 *
 * @see my_syslog() for non-fatal error logging
 * @see flush_log() for queue draining before exit
 *
 * EXAMPLE USAGE:
 * @code
 * // Bind failure during startup
 * if (bind(sock_fd, &addr, sizeof(addr)) < 0)
 *   die("Cannot bind to port %d: %s", "53", 1);  // arg1="53", errno explains bind failure
 * 
 * // Configuration file error
 * if (!parse_config(config_file))
 *   die("Bad configuration file: %s", config_file, 1);
 * 
 * // Using NULL to get errno in first position
 * if (chdir("/var/lib/dnsmasq") < 0)
 *   die("Cannot change directory: %s", NULL, 1);  // NULL causes strerror(errno) as first arg
 * @endcode
 *
 * SIDE EFFECTS:
 * - Logs error message with LOG_CRIT priority via my_syslog()
 * - Logs "FAILED to start up" message with LOG_CRIT priority
 * - Temporarily modifies echo_stderr global to force stderr output
 * - Calls flush_log() which drains queue and closes log_fd
 * - Terminates process via exit() with specified exit code - DOES NOT RETURN
 * - If !log_stderr initially, prints newline to stderr for formatting
 *
 * THREAD SAFETY:
 * Not thread-safe due to global state modification (echo_stderr). Should only be
 * called from main thread. However, this is a termination function so thread safety
 * after call is irrelevant - process terminates. The logging calls are safe in
 * single-threaded context.
 */
void die(char *message, char *arg1, int exit_code)
{
  char *errmess = strerror(errno);
  
  if (!arg1)
    arg1 = errmess;

  if (!log_stderr)
    {
      echo_stderr = 1; /* print as well as log when we die.... */
      fputc('\n', stderr); /* prettyfy  startup-script message */
    }
  my_syslog(LOG_CRIT, message, arg1, errmess);
  echo_stderr = 0;
  my_syslog(LOG_CRIT, _("FAILED to start up"));
  flush_log();
  
  exit(exit_code);
}
