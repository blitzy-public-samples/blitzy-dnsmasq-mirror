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
 * @file inotify.c
 * @brief Linux inotify integration for dynamic configuration monitoring
 *
 * DETAILED PURPOSE:
 * This file implements Linux inotify(7) API integration to enable automatic
 * monitoring of configuration files and directories. When HAVE_INOTIFY is defined,
 * dnsmasq uses inotify to watch resolv.conf files and dynamic configuration
 * directories (--dhcp-hostsdir, --hostsdir) for changes. File modifications,
 * creations, or moves trigger automatic reloading without requiring manual SIGHUP
 * signals. This provides seamless configuration updates for containerized and
 * dynamic environments.
 *
 * The implementation uses a single inotify file descriptor to monitor multiple
 * directories. When events occur (IN_CLOSE_WRITE or IN_MOVED_TO), the event
 * handler identifies which configuration file changed and triggers appropriate
 * reload actions: poll_resolv() for DNS server updates, read_hostsfile() for
 * hosts file updates, or option_read_dynfile() for DHCP configuration updates.
 *
 * KEY RESPONSIBILITIES:
 * - inotify_dnsmasq_init(): Initialize inotify watches for resolv-file directories
 * - set_dynamic_inotify(): Setup watches for dynamic directories and read initial contents
 * - inotify_check(): Process inotify events and trigger configuration reloads
 * - my_readlink(): Follow symbolic links to their targets for watch setup
 *
 * DEPENDENCIES:
 * - dnsmasq.h: Daemon structures (struct resolvc, struct hostsfile, struct daemon)
 * - sys/inotify.h: Linux inotify API (inotify_init1, inotify_add_watch, inotify_event)
 * - sys/param.h: MAXSYMLINKS constant for symlink loop detection
 * - readlink(2): Resolve symbolic links to actual file paths
 *
 * DATA STRUCTURES:
 * - inotify_buffer: Static buffer for reading inotify events (INOTIFY_SZ bytes)
 * - struct resolvc (dnsmasq.h:664-674): Resolv file descriptor with wd (watch descriptor)
 * - struct hostsfile (dnsmasq.h:683-691): Hosts file descriptor with wd and flags
 * - daemon->inotifyfd: Global inotify file descriptor in daemon structure
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_INOTIFY: Entire file conditionally compiled, Linux-specific feature
 * - HAVE_DHCP: Enables DHCP hosts/opts file monitoring within set_dynamic_inotify()
 *
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven model. inotify_check() called from main event loop
 * when inotifyfd becomes readable. Non-blocking I/O (IN_NONBLOCK) prevents event
 * loop blocking. No locking required due to single-threaded architecture.
 *
 * STRATEGY:
 * Set inotify watches on directories containing resolv files, not the files themselves.
 * This handles files being replaced atomically (common with configuration management
 * tools). When directory events fire (close-write or move-to), check if the affected
 * file is actually a monitored resolv file, then force poll_resolv() reload.
 *
 * ERROR CONDITION:
 * All directories containing specified resolv-files must exist at startup, even if
 * the actual files don't exist yet. Missing directories cause fatal error at init.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"
#ifdef HAVE_INOTIFY

#include <sys/inotify.h>
#include <sys/param.h> /* For MAXSYMLINKS */

/* the strategy is to set an inotify on the directories containing
   resolv files, for any files in the directory which are close-write 
   or moved into the directory.
   
   When either of those happen, we look to see if the file involved
   is actually a resolv-file, and if so, call poll-resolv with
   the "force" argument, to ensure it's read.

   This adds one new error condition: the directories containing
   all specified resolv-files must exist at start-up, even if the actual
   files don't. 
*/

static char *inotify_buffer;
#define INOTIFY_SZ (sizeof(struct inotify_event) + NAME_MAX + 1)

/**
 * @brief Resolve symbolic link to its target path with absolute path conversion
 *
 * @detailed
 * Resolves a symbolic link to the path it points to, converting relative paths
 * to absolute paths by prepending the directory component of the original path.
 * Dynamically allocates buffer sized appropriately for the link target (starting
 * at 64 bytes, growing by 64 bytes until sufficient). If path is not a symlink
 * or doesn't exist, returns NULL. Used to follow symlink chains for resolv-file
 * paths before setting up inotify watches on containing directories.
 *
 * @param[in] path Path to check for symbolic link (may be relative or absolute)
 *
 * @return Malloc'd string containing absolute path to link target, or NULL if
 *         path is not a symlink or doesn't exist (EINVAL/ENOENT). Caller must
 *         free returned pointer.
 *
 * @retval NULL Path is not a symbolic link (EINVAL) or doesn't exist (ENOENT)
 * @retval char* Absolute path to symbolic link target (caller must free)
 *
 * @note Buffer size starts at 64 bytes and grows dynamically until readlink succeeds
 * @note Relative link targets are converted to absolute by prepending directory path
 * @note Dies with EC_MISC if readlink fails with error other than EINVAL/ENOENT
 *
 * @warning Allocates memory that caller must free to avoid leaks
 * @warning Dies on unexpected readlink() errors (permissions, I/O errors)
 *
 * @see inotify_dnsmasq_init() which uses this to follow symlink chains
 *
 * EXAMPLE USAGE:
 * @code
 * char *target = my_readlink("/etc/resolv.conf");
 * if (target) {
 *   // resolv.conf is a symlink, target contains actual path
 *   printf("Symlink points to: %s\n", target);
 *   free(target);
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates memory with safe_malloc() that must be freed by caller
 * - Calls die() on unexpected errors (aborts program)
 *
 * THREAD SAFETY:
 * Re-entrant. Uses only local stack variables and thread-safe system calls.
 */
static char *my_readlink(char *path)
{
  ssize_t rc, size = 64;
  char *buf;

  while (1)
    {
      buf = safe_malloc(size);
      rc = readlink(path, buf, (size_t)size);
      
      if (rc == -1)
	{
	  /* Not link or doesn't exist. */
	  if (errno == EINVAL || errno == ENOENT)
	    {
	      free(buf);
	      return NULL;
	    }
	  else
	    die(_("cannot access path %s: %s"), path, EC_MISC);
	}
      else if (rc < size-1)
	{
	  char *d;
	  
	  buf[rc] = 0;
	  if (buf[0] != '/' && ((d = strrchr(path, '/'))))
	    {
	      /* Add path to relative link */
	      char *new_buf = safe_malloc((d - path) + strlen(buf) + 2);
	      *(d+1) = 0;
	      strcpy(new_buf, path);
	      strcat(new_buf, buf);
	      free(buf);
	      buf = new_buf;
	    }
	  return buf;
	}

      /* Buffer too small, increase and retry */
      size += 64;
      free(buf);
    }
}

/**
 * @brief Initialize inotify watches for resolv-file directories
 *
 * @detailed
 * Creates inotify file descriptor and sets up watches on directories containing
 * resolv-files (DNS server configuration files like /etc/resolv.conf). Follows
 * symbolic link chains up to MAXSYMLINKS depth to find actual file locations,
 * then monitors parent directories for IN_CLOSE_WRITE and IN_MOVED_TO events.
 * This approach handles files being atomically replaced by configuration tools.
 * Stores watch descriptors (wd) and filename pointers in struct resolvc entries
 * for later event matching in inotify_check(). Dies with fatal error if inotify
 * initialization fails or if any resolv-file directory doesn't exist at startup.
 *
 * @param None (operates on global daemon->resolv_files list)
 *
 * @return void (dies on error, no return value on success)
 *
 * @note Allocates inotify_buffer with INOTIFY_SZ bytes for event reading
 * @note Sets daemon->inotifyfd to inotify file descriptor (non-blocking, close-on-exec)
 * @note Early return if OPT_NO_RESOLV flag set (no resolv files to monitor)
 * @note Follows symlinks up to MAXSYMLINKS (typically 20) to avoid infinite loops
 * @note Watch descriptors stored in res->wd, filename pointers in res->file
 *
 * @warning Dies with EC_MISC if inotify_init1() fails (insufficient resources)
 * @warning Dies with EC_MISC if directory for resolv-file doesn't exist (ENOENT)
 * @warning Dies with EC_MISC if inotify_add_watch() fails for any resolv-file
 * @warning Dies with EC_MISC if symlink chain exceeds MAXSYMLINKS depth
 *
 * @see inotify_check() which processes events from these watches
 * @see my_readlink() which resolves symbolic links in resolv-file paths
 * @see struct resolvc (dnsmasq.h:664-674) for resolv file descriptor structure
 *
 * EXAMPLE USAGE:
 * @code
 * // Called once during daemon initialization
 * daemon->resolv_files = configure_resolv_files();
 * inotify_dnsmasq_init(); // Sets up watches
 * // Later in event loop: if (poll() indicates inotifyfd readable) inotify_check()
 * @endcode
 *
 * SIDE EFFECTS:
 * - Creates global inotify file descriptor (daemon->inotifyfd)
 * - Allocates inotify_buffer static global buffer (INOTIFY_SZ bytes)
 * - Modifies daemon->resolv_files entries (sets wd and file fields)
 * - Calls inotify_init1() and inotify_add_watch() system calls
 * - May abort program with die() on initialization failures
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called once during single-threaded initialization
 * before entering event loop. Modifies global daemon structure.
 */
void inotify_dnsmasq_init()
{
  struct resolvc *res;
  inotify_buffer = safe_malloc(INOTIFY_SZ);
  daemon->inotifyfd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  
  if (daemon->inotifyfd == -1)
    die(_("failed to create inotify: %s"), NULL, EC_MISC);

  if (option_bool(OPT_NO_RESOLV))
    return;
  
  for (res = daemon->resolv_files; res; res = res->next)
    {
      char *d, *new_path, *path = safe_malloc(strlen(res->name) + 1);
      int links = MAXSYMLINKS;

      strcpy(path, res->name);

      /* Follow symlinks until we reach a non-symlink, or a non-existent file. */
      while ((new_path = my_readlink(path)))
	{
	  if (links-- == 0)
	    die(_("too many symlinks following %s"), res->name, EC_MISC);
	  free(path);
	  path = new_path;
	}

      res->wd = -1;

      if ((d = strrchr(path, '/')))
	{
	  *d = 0; /* make path just directory */
	  res->wd = inotify_add_watch(daemon->inotifyfd, path, IN_CLOSE_WRITE | IN_MOVED_TO);

	  res->file = d+1; /* pointer to filename */
	  *d = '/';
	  
	  if (res->wd == -1 && errno == ENOENT)
	    die(_("directory %s for resolv-file is missing, cannot poll"), res->name, EC_MISC);
	}	  
	 
      if (res->wd == -1)
	die(_("failed to create inotify for %s: %s"), res->name, EC_MISC);
	
    }
}

/**
 * @brief Initialize inotify watches for dynamic directories and load existing files
 *
 * @detailed
 * Sets up inotify watches on dynamic configuration directories (--dhcp-hostsdir,
 * --hostsdir) specified with matching flags (AH_HOSTS, AH_DHCP_HST, AH_DHCP_OPT).
 * Validates each directory exists and is actually a directory, then adds inotify
 * watch for IN_CLOSE_WRITE and IN_MOVED_TO events. After establishing watch, reads
 * all existing files in directory to load initial configuration (avoiding race
 * condition where files added during startup might be missed). Ignores emacs
 * backup files (~), lock files (#...#), dotfiles, and non-regular files. For hosts
 * files, calls read_hostsfile() and optionally triggers DHCP lease updates. For
 * DHCP configuration files, calls option_read_dynfile() to load options/hosts.
 *
 * @param[in] flag Filter flags (AH_HOSTS, AH_DHCP_HST, AH_DHCP_OPT) to select directories
 * @param[in] total_size Current total cache size for read_hostsfile() (hosts files only)
 * @param[in] rhash Reverse hash table pointer for read_hostsfile() (hosts files only)
 * @param[in] revhashsz Reverse hash table size for read_hostsfile() (hosts files only)
 *
 * @return void (errors logged to syslog, no fatal errors)
 *
 * @note Only processes directories with flags matching input flag parameter
 * @note Sets AH_WD_DONE flag after creating watch to avoid duplicate watches
 * @note Reads directory contents AFTER adding watch to minimize race window
 * @note Ignores files ending with '~', starting/ending with '#', or starting with '.'
 * @note Only processes regular files (S_ISREG), ignores directories and special files
 *
 * @warning Logs errors to syslog for invalid directories or inotify failures (non-fatal)
 * @warning Allocates temporary path strings with whine_malloc (may fail silently on OOM)
 *
 * @see inotify_check() which processes events from these watches
 * @see struct hostsfile (dnsmasq.h:683-691) for dynamic directory descriptor
 * @see read_hostsfile() for hosts file parsing
 * @see option_read_dynfile() for DHCP option/host parsing
 *
 * EXAMPLE USAGE:
 * @code
 * // Called during initialization and optionally on SIGHUP reload
 * set_dynamic_inotify(AH_HOSTS, 0, daemon->cache_hash, daemon->hash_size);
 * #ifdef HAVE_DHCP
 * set_dynamic_inotify(AH_DHCP_HST | AH_DHCP_OPT, 0, NULL, 0);
 * #endif
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies daemon->dynamic_dirs entries (sets wd field, sets AH_WD_DONE flag)
 * - Calls inotify_add_watch() system call for each matching directory
 * - Loads all existing files in directories via read_hostsfile() or option_read_dynfile()
 * - May trigger DHCP configuration updates (dhcp_update_configs, lease updates) for hosts
 * - Logs errors and warnings to syslog (my_syslog)
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon structure. Must be called from main thread
 * during initialization or configuration reload (single-threaded sections).
 */
void set_dynamic_inotify(int flag, int total_size, struct crec **rhash, int revhashsz)
{
  struct hostsfile *ah;
  
  for (ah = daemon->dynamic_dirs; ah; ah = ah->next)
    {
      DIR *dir_stream = NULL;
      struct dirent *ent;
      struct stat buf;
     
      if (!(ah->flags & flag))
	continue;
 
      if (stat(ah->fname, &buf) == -1)
	{
	  my_syslog(LOG_ERR, _("bad dynamic directory %s: %s"), 
		    ah->fname, strerror(errno));
	  continue;
	}

      if (!(S_ISDIR(buf.st_mode)))
	{
	  my_syslog(LOG_ERR, _("bad dynamic directory %s: %s"), 
		    ah->fname, _("not a directory"));
	  continue;
	}
      
       if (!(ah->flags & AH_WD_DONE))
	 {
	   ah->wd = inotify_add_watch(daemon->inotifyfd, ah->fname, IN_CLOSE_WRITE | IN_MOVED_TO);
	   ah->flags |= AH_WD_DONE;
	 }

       /* Read contents of dir _after_ calling add_watch, in the hope of avoiding
	  a race which misses files being added as we start */
       if (ah->wd == -1 || !(dir_stream = opendir(ah->fname)))
	 {
	   my_syslog(LOG_ERR, _("failed to create inotify for %s: %s"),
		     ah->fname, strerror(errno));
	   continue;
	 }

       while ((ent = readdir(dir_stream)))
	 {
	   size_t lendir = strlen(ah->fname);
	   size_t lenfile = strlen(ent->d_name);
	   char *path;
	   
	   /* ignore emacs backups and dotfiles */
	   if (lenfile == 0 || 
	       ent->d_name[lenfile - 1] == '~' ||
	       (ent->d_name[0] == '#' && ent->d_name[lenfile - 1] == '#') ||
	       ent->d_name[0] == '.')
	     continue;
	   
	   if ((path = whine_malloc(lendir + lenfile + 2)))
	     {
	       strcpy(path, ah->fname);
	       strcat(path, "/");
	       strcat(path, ent->d_name);
	       
	       /* ignore non-regular files */
	       if (stat(path, &buf) != -1 && S_ISREG(buf.st_mode))
		 {
		   if (ah->flags & AH_HOSTS)
		     total_size = read_hostsfile(path, ah->index, total_size, rhash, revhashsz);
#ifdef HAVE_DHCP
		   else if (ah->flags & (AH_DHCP_HST | AH_DHCP_OPT))
		     option_read_dynfile(path, ah->flags);
#endif		   
		 }

	       free(path);
	     }
	 }

       closedir(dir_stream);
    }
}

/**
 * @brief Process inotify events and trigger configuration reloads
 *
 * @detailed
 * Reads available inotify events from daemon->inotifyfd and processes each event
 * to determine which configuration file changed. For resolv-file events, sets hit
 * flag to trigger DNS server list reload. For dynamic directory events (hosts,
 * DHCP configuration), immediately reloads the affected file and propagates changes
 * (cache updates, DHCP lease updates). Handles multiple events in single read buffer.
 * Ignores emacs backup files (~), lock files (#...#), and dotfiles. Called from
 * main event loop when inotifyfd becomes readable, processes all pending events
 * until EAGAIN/EWOULDBLOCK.
 *
 * @param[in] now Current time for lease file updates (from time(NULL) or monotonic clock)
 *
 * @return 1 if resolv-file changed (caller should trigger poll_resolv), 0 otherwise
 *
 * @retval 0 No resolv-file events detected (only dynamic dir events or no events)
 * @retval 1 At least one resolv-file change detected, caller should reload DNS servers
 *
 * @note Handles IN_CLOSE_WRITE and IN_MOVED_TO events (setup in init functions)
 * @note Ignores zero-length names and backup/temporary/hidden files
 * @note Matches events to resolv files by comparing wd and filename
 * @note Matches events to dynamic dirs by comparing wd only
 * @note Logs dynamic file changes to syslog at INFO level
 * @note Processes all available events in single call (loop until read returns <=0)
 *
 * @warning Assumes inotify_buffer allocated by inotify_dnsmasq_init() before use
 * @warning May trigger expensive operations (file I/O, cache rebuilds, DHCP updates)
 *
 * @see inotify_dnsmasq_init() which sets up resolv-file watches
 * @see set_dynamic_inotify() which sets up dynamic directory watches
 * @see read_hostsfile() for hosts file reloading
 * @see option_read_dynfile() for DHCP configuration reloading
 *
 * EXAMPLE USAGE:
 * @code
 * // In main event loop after poll() indicates inotifyfd readable
 * if (poll_result[inotify_index].revents & POLLIN) {
 *   if (inotify_check(now)) {
 *     poll_resolv(1, 0, now); // Force reload DNS servers
 *   }
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly tied to RFCs. Provides operational feature for dynamic reconfiguration
 * without service interruption, supporting containerized/cloud environments.
 *
 * SIDE EFFECTS:
 * - Reads from daemon->inotifyfd (may return EINTR, handled with retry loop)
 * - May call read_hostsfile() which rebuilds DNS cache entries
 * - May call option_read_dynfile() which modifies DHCP configuration
 * - May trigger dhcp_update_configs(), lease_update_from_configs(), lease_update_file()
 * - May trigger lease_update_dns() which modifies DNS cache from DHCP leases
 * - Logs file change events to syslog (my_syslog at LOG_INFO level)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop thread only. Modifies global
 * daemon state (cache, DHCP configuration). Assumes single-threaded event model.
 */
int inotify_check(time_t now)
{
  int hit = 0;
  struct hostsfile *ah;

  while (1)
    {
      int rc;
      char *p;
      struct resolvc *res;
      struct inotify_event *in;

      while ((rc = read(daemon->inotifyfd, inotify_buffer, INOTIFY_SZ)) == -1 && errno == EINTR);
      
      if (rc <= 0)
	break;
      
      for (p = inotify_buffer; rc - (p - inotify_buffer) >= (int)sizeof(struct inotify_event); p += sizeof(struct inotify_event) + in->len) 
	{
	  size_t namelen;

	  in = (struct inotify_event*)p;
	  
	  /* ignore emacs backups and dotfiles */
	  if (in->len == 0 || (namelen = strlen(in->name)) == 0 ||
	      in->name[namelen - 1] == '~' ||
	      (in->name[0] == '#' && in->name[namelen - 1] == '#') ||
	      in->name[0] == '.')
	    continue;

	  for (res = daemon->resolv_files; res; res = res->next)
	    if (res->wd == in->wd && strcmp(res->file, in->name) == 0)
	      hit = 1;

	  for (ah = daemon->dynamic_dirs; ah; ah = ah->next)
	    if (ah->wd == in->wd)
	      {
		size_t lendir = strlen(ah->fname);
		char *path;
		
		if ((path = whine_malloc(lendir + in->len + 2)))
		  {
		    strcpy(path, ah->fname);
		    strcat(path, "/");
		    strcat(path, in->name);
		     
		    my_syslog(LOG_INFO, _("inotify, new or changed file %s"), path);

		    if (ah->flags & AH_HOSTS)
		      {
			read_hostsfile(path, ah->index, 0, NULL, 0);
#ifdef HAVE_DHCP
			if (daemon->dhcp || daemon->doing_dhcp6) 
			  {
			    /* Propagate the consequences of loading a new dhcp-host */
			    dhcp_update_configs(daemon->dhcp_conf);
			    lease_update_from_configs(); 
			    lease_update_file(now); 
			    lease_update_dns(1);
			  }
#endif
		      }
#ifdef HAVE_DHCP
		    else if (ah->flags & AH_DHCP_HST)
		      {
			if (option_read_dynfile(path, AH_DHCP_HST))
			  {
			    /* Propagate the consequences of loading a new dhcp-host */
			    dhcp_update_configs(daemon->dhcp_conf);
			    lease_update_from_configs(); 
			    lease_update_file(now); 
			    lease_update_dns(1);
			  }
		      }
		    else if (ah->flags & AH_DHCP_OPT)
		      option_read_dynfile(path, AH_DHCP_OPT);
#endif
		    
		    free(path);
		  }
	      }
	}
    }
  return hit;
}

#endif  /* INOTIFY */
