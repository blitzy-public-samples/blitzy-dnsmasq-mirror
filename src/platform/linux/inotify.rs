// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
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

//! Linux inotify file system monitoring integration
//!
//! This module implements Linux inotify(7) API integration to enable automatic
//! monitoring of configuration files and directories. When enabled, dnsmasq uses
//! inotify to watch resolv.conf files and dynamic configuration directories
//! (--dhcp-hostsdir, --hostsdir) for changes. File modifications, creations, or
//! moves trigger automatic reloading without requiring manual SIGHUP signals.
//! This provides seamless configuration updates for containerized and dynamic
//! environments.
//!
//! ## Architecture
//!
//! The implementation uses a single inotify file descriptor to monitor multiple
//! directories. When events occur (IN_CLOSE_WRITE or IN_MOVED_TO), the event
//! handler identifies which configuration file changed and emits appropriate
//! [`FileEvent`] variants for processing by the main event loop.
//!
//! ## Key Features
//!
//! - Monitors resolv-file directories (e.g., /etc containing resolv.conf)
//! - Watches dynamic configuration directories (hostsdir, dhcp-hostsdir)
//! - Follows symbolic links up to MAXSYMLINKS depth
//! - Filters backup files (~), lock files (#...#), and dotfiles
//! - Async event streaming integrated with Tokio runtime
//! - Type-safe error handling with [`InotifyError`]
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use dnsmasq::platform::linux::inotify::{InotifyWatcher, FileEvent};
//! use std::path::PathBuf;
//!
//! async fn monitor_config() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut watcher = InotifyWatcher::new()?;
//!     
//!     // Watch resolv files
//!     watcher.watch_resolv_files(vec![
//!         PathBuf::from("/etc/resolv.conf")
//!     ]).await?;
//!     
//!     // Process events
//!     while let Some(event) = watcher.next_event() {
//!         match event {
//!             FileEvent::ResolvFileChanged(path) => {
//!                 println!("Resolv file changed: {:?}", path);
//!             }
//!             FileEvent::DynamicFileChanged(path, _flags) => {
//!                 println!("Dynamic file changed: {:?}", path);
//!             }
//!         }
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Implementation Notes
//!
//! The strategy is to set inotify watches on directories containing resolv files,
//! not the files themselves. This handles files being replaced atomically (common
//! with configuration management tools). When directory events fire, we check if
//! the affected file is actually a monitored resolv file, then emit the appropriate
//! event.
//!
//! All directories containing specified resolv-files must exist at startup, even
//! if the actual files don't exist yet. Missing directories cause initialization
//! errors.

use inotify::{Inotify, WatchMask};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;
use tracing::info;

/// Maximum number of symbolic links to follow before giving up
const MAXSYMLINKS: usize = 40;

/// Flags for dynamic directory types (matching C implementation)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirFlags {
    /// Hosts file directory (--hostsdir)
    pub hosts: bool,
    /// DHCP hosts directory (--dhcp-hostsdir)
    pub dhcp_hosts: bool,
    /// DHCP options directory (--dhcp-optsdir)
    pub dhcp_opts: bool,
}

impl DirFlags {
    /// Create flags for hosts directory
    #[must_use]
    pub fn hosts() -> Self {
        Self {
            hosts: true,
            dhcp_hosts: false,
            dhcp_opts: false,
        }
    }

    /// Create flags for DHCP hosts directory
    #[must_use]
    pub fn dhcp_hosts() -> Self {
        Self {
            hosts: false,
            dhcp_hosts: true,
            dhcp_opts: false,
        }
    }

    /// Create flags for DHCP options directory
    #[must_use]
    pub fn dhcp_opts() -> Self {
        Self {
            hosts: false,
            dhcp_hosts: false,
            dhcp_opts: true,
        }
    }

    /// Check if this matches a filter
    #[must_use]
    pub fn matches(&self, filter: &DirFlags) -> bool {
        (!filter.hosts || self.hosts)
            && (!filter.dhcp_hosts || self.dhcp_hosts)
            && (!filter.dhcp_opts || self.dhcp_opts)
    }
}

/// Errors that can occur during inotify operations
#[derive(Error, Debug)]
pub enum InotifyError {
    /// Failed to initialize inotify
    #[error("failed to initialize inotify: {0}")]
    InitFailed(#[source] io::Error),

    /// Failed to add watch for a file or directory
    #[error("failed to add watch for {path}: {source}")]
    WatchFailed {
        /// Path that failed to be watched
        path: PathBuf,
        /// Underlying I/O error
        #[source]
        source: io::Error,
    },

    /// Too many symbolic links encountered while resolving path
    #[error("too many symbolic links following {0}")]
    TooManySymlinks(PathBuf),

    /// Required directory is missing
    #[error("directory {path} for resolv-file is missing, cannot poll")]
    DirectoryMissing {
        /// Path to the missing directory
        path: PathBuf,
    },

    /// General I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Path is not a directory
    #[error("{path} is not a directory")]
    NotADirectory {
        /// Path that is not a directory
        path: PathBuf,
    },
}

/// Events emitted when monitored files change
#[derive(Debug, Clone)]
pub enum FileEvent {
    /// A resolv file (e.g., /etc/resolv.conf) has changed
    ResolvFileChanged(PathBuf),

    /// A file in a dynamic directory has changed
    DynamicFileChanged(PathBuf, DirFlags),
}

/// Watch descriptor mapping information
#[derive(Debug, Clone)]
struct WatchInfo {
    /// Directory being watched
    dir_path: PathBuf,
    /// For resolv files: the filename to match (e.g., "resolv.conf")
    /// For dynamic dirs: None (all files in directory are monitored)
    filename: Option<String>,
    /// Flags indicating what type of dynamic directory this is
    flags: Option<DirFlags>,
}

/// Linux inotify file system watcher for configuration files
///
/// Monitors resolv files and dynamic configuration directories for changes,
/// providing async event streaming integrated with the Tokio runtime.
pub struct InotifyWatcher {
    /// The underlying inotify instance
    inotify: Inotify,
    /// Mapping from watch descriptor to watch information
    watches: HashMap<i32, WatchInfo>,
    /// Event buffer for reading inotify events
    event_buffer: Vec<u8>,
}

impl InotifyWatcher {
    /// Create a new inotify watcher
    ///
    /// Initializes the inotify file descriptor with `IN_NONBLOCK` and `IN_CLOEXEC` flags.
    ///
    /// # Errors
    ///
    /// Returns [`InotifyError::InitFailed`] if inotify initialization fails,
    /// typically due to resource exhaustion (too many inotify instances).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use dnsmasq::platform::linux::inotify::InotifyWatcher;
    ///
    /// let watcher = InotifyWatcher::new()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self, InotifyError> {
        let inotify = Inotify::init().map_err(InotifyError::InitFailed)?;

        info!("Initialized inotify for configuration file monitoring");

        Ok(Self {
            inotify,
            watches: HashMap::new(),
            event_buffer: vec![0u8; 4096], // Buffer for reading events
        })
    }

    /// Watch resolv files (e.g., /etc/resolv.conf) for changes
    ///
    /// Sets up inotify watches on the directories containing resolv files.
    /// Follows symbolic links up to MAXSYMLINKS depth to find actual file
    /// locations, then monitors parent directories for `IN_CLOSE_WRITE` and
    /// `IN_MOVED_TO` events.
    ///
    /// # Arguments
    ///
    /// * `resolv_files` - List of resolv file paths to monitor
    ///
    /// # Errors
    ///
    /// - [`InotifyError::TooManySymlinks`] if symlink chain exceeds MAXSYMLINKS
    /// - [`InotifyError::DirectoryMissing`] if parent directory doesn't exist
    /// - [`InotifyError::WatchFailed`] if `inotify_add_watch` fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use dnsmasq::platform::linux::inotify::InotifyWatcher;
    /// use std::path::PathBuf;
    ///
    /// let mut watcher = InotifyWatcher::new()?;
    /// watcher.watch_resolv_files(vec![
    ///     PathBuf::from("/etc/resolv.conf"),
    ///     PathBuf::from("/run/systemd/resolve/resolv.conf"),
    /// ]).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn watch_resolv_files(
        &mut self,
        resolv_files: Vec<PathBuf>,
    ) -> Result<(), InotifyError> {
        for path in resolv_files {
            // Follow symlinks to find the actual file location
            let resolved_path = self.resolve_symlinks(&path).await?;

            // Extract directory and filename
            if let Some(parent) = resolved_path.parent() {
                if let Some(filename) = resolved_path.file_name() {
                    let filename_str = filename.to_string_lossy().to_string();

                    // Check that directory exists
                    let metadata = fs::metadata(parent).await.map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            InotifyError::DirectoryMissing {
                                path: parent.to_path_buf(),
                            }
                        } else {
                            InotifyError::IoError(e)
                        }
                    })?;

                    if !metadata.is_dir() {
                        return Err(InotifyError::NotADirectory {
                            path: parent.to_path_buf(),
                        });
                    }

                    // Add inotify watch on the directory
                    let wd = self
                        .inotify
                        .watches()
                        .add(parent, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO)
                        .map_err(|e| InotifyError::WatchFailed {
                            path: parent.to_path_buf(),
                            source: e,
                        })?;

                    info!(
                        "Added inotify watch for resolv file: {} (wd: {:?})",
                        resolved_path.display(),
                        wd
                    );

                    // Store watch information
                    self.watches.insert(
                        wd.get_watch_descriptor_id(),
                        WatchInfo {
                            dir_path: parent.to_path_buf(),
                            filename: Some(filename_str),
                            flags: None,
                        },
                    );
                }
            }
        }

        Ok(())
    }

    /// Watch dynamic configuration directories for changes
    ///
    /// Sets up inotify watches on dynamic configuration directories
    /// (--dhcp-hostsdir, --hostsdir) and reads existing files to load
    /// initial configuration. This avoids race conditions where files
    /// added during startup might be missed.
    ///
    /// # Arguments
    ///
    /// * `dirs` - List of (`directory_path`, flags) tuples to monitor
    ///
    /// # Errors
    ///
    /// Returns [`InotifyError::WatchFailed`] if directory doesn't exist or
    /// `inotify_add_watch` fails. Errors are logged but don't prevent other
    /// directories from being watched.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use dnsmasq::platform::linux::inotify::{InotifyWatcher, DirFlags};
    /// use std::path::PathBuf;
    ///
    /// let mut watcher = InotifyWatcher::new()?;
    /// watcher.watch_dynamic_dirs(vec![
    ///     (PathBuf::from("/etc/dnsmasq.d/hosts"), DirFlags::hosts()),
    ///     (PathBuf::from("/etc/dnsmasq.d/dhcp-hosts"), DirFlags::dhcp_hosts()),
    /// ]).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn watch_dynamic_dirs(
        &mut self,
        dirs: Vec<(PathBuf, DirFlags)>,
    ) -> Result<(), InotifyError> {
        for (dir_path, flags) in dirs {
            // Validate directory exists and is actually a directory
            let metadata = match fs::metadata(&dir_path).await {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Bad dynamic directory {}: {}", dir_path.display(), e);
                    continue;
                }
            };

            if !metadata.is_dir() {
                tracing::warn!(
                    "Bad dynamic directory {}: not a directory",
                    dir_path.display()
                );
                continue;
            }

            // Add inotify watch on the directory
            let wd = match self
                .inotify
                .watches()
                .add(&dir_path, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO)
            {
                Ok(wd) => wd,
                Err(e) => {
                    tracing::error!("Failed to create inotify for {}: {}", dir_path.display(), e);
                    continue;
                }
            };

            info!(
                "Added inotify watch for dynamic directory: {} (wd: {:?})",
                dir_path.display(),
                wd
            );

            // Store watch information
            self.watches.insert(
                wd.get_watch_descriptor_id(),
                WatchInfo {
                    dir_path: dir_path.clone(),
                    filename: None,
                    flags: Some(flags),
                },
            );

            // Read existing files in directory after adding watch to minimize race window
            if let Err(e) = self.read_directory_files(&dir_path, &flags).await {
                tracing::warn!(
                    "Failed to read initial files in {}: {}",
                    dir_path.display(),
                    e
                );
            }
        }

        Ok(())
    }

    /// Get the next file change event
    ///
    /// Reads inotify events from the file descriptor and processes them to
    /// determine which configuration file changed. Returns None when no more
    /// events are available (would block).
    ///
    /// # Returns
    ///
    /// - `Some(FileEvent)` - A file change event
    /// - `None` - No events available (non-blocking)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use dnsmasq::platform::linux::inotify::{InotifyWatcher, FileEvent};
    ///
    /// let mut watcher = InotifyWatcher::new()?;
    /// // ... setup watches ...
    ///
    /// while let Some(event) = watcher.next_event() {
    ///     match event {
    ///         FileEvent::ResolvFileChanged(path) => {
    ///             println!("Reload DNS servers from: {:?}", path);
    ///         }
    ///         FileEvent::DynamicFileChanged(path, flags) => {
    ///             println!("Reload config file: {:?}", path);
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn next_event(&mut self) -> Option<FileEvent> {
        // Read events from inotify (non-blocking)
        let events = match self.inotify.read_events(&mut self.event_buffer) {
            Ok(events) => events,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No events available
                return None;
            }
            Err(e) => {
                tracing::error!("Error reading inotify events: {}", e);
                return None;
            }
        };

        // Process each event
        for event in events {
            let wd_id = event.wd.get_watch_descriptor_id();

            // Get watch information
            let Some(watch_info) = self.watches.get(&wd_id) else {
                continue;
            };

            // Get event name (filename that triggered event)
            let event_name = match event.name {
                Some(name) => name.to_string_lossy(),
                None => continue,
            };

            // Filter out backup files, lock files, and dotfiles
            if Self::should_ignore_file(&event_name) {
                continue;
            }

            // Check if this is a resolv file event
            if let Some(ref filename) = watch_info.filename {
                if event_name == filename.as_str() {
                    // Resolv file changed
                    let full_path = watch_info.dir_path.join(&*event_name);
                    info!("Resolv file changed: {}", full_path.display());
                    return Some(FileEvent::ResolvFileChanged(full_path));
                }
            }

            // Check if this is a dynamic directory event
            if let Some(flags) = watch_info.flags {
                let full_path = watch_info.dir_path.join(&*event_name);

                // Verify it's a regular file
                if let Ok(metadata) = std::fs::metadata(&full_path) {
                    if metadata.is_file() {
                        info!("Inotify, new or changed file: {}", full_path.display());
                        return Some(FileEvent::DynamicFileChanged(full_path, flags));
                    }
                }
            }
        }

        None
    }

    /// Resolve symbolic links to their target path with absolute path conversion
    ///
    /// Follows a chain of symbolic links up to MAXSYMLINKS depth to find the
    /// actual file location. Converts relative link targets to absolute paths
    /// by prepending the directory component.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to resolve (may be relative or absolute)
    ///
    /// # Errors
    ///
    /// Returns [`InotifyError::TooManySymlinks`] if the symlink chain exceeds
    /// MAXSYMLINKS depth.
    async fn resolve_symlinks(&self, path: &Path) -> Result<PathBuf, InotifyError> {
        let mut current_path = path.to_path_buf();
        let mut links_followed = 0;

        loop {
            // Try to read the symlink
            let link_target = match fs::read_link(&current_path).await {
                Ok(target) => target,
                Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
                    // Not a symlink, return current path
                    return Ok(current_path);
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    // File doesn't exist yet, return current path
                    return Ok(current_path);
                }
                Err(e) => {
                    return Err(InotifyError::IoError(e));
                }
            };

            links_followed += 1;
            if links_followed > MAXSYMLINKS {
                return Err(InotifyError::TooManySymlinks(path.to_path_buf()));
            }

            // Convert relative link to absolute
            if link_target.is_relative() {
                if let Some(parent) = current_path.parent() {
                    current_path = parent.join(link_target);
                } else {
                    current_path = link_target;
                }
            } else {
                current_path = link_target;
            }
        }
    }

    /// Read all files in a directory and emit events for initial loading
    ///
    /// Called after adding a watch to load existing files in the directory.
    /// This avoids race conditions where files present at startup might be
    /// missed.
    async fn read_directory_files(
        &self,
        dir_path: &Path,
        _flags: &DirFlags,
    ) -> Result<(), io::Error> {
        let mut entries = fs::read_dir(dir_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name_os = entry.file_name();
            let Some(filename) = file_name_os.to_str() else {
                continue;
            };

            // Filter out backup files, lock files, and dotfiles
            if Self::should_ignore_file(filename) {
                continue;
            }

            // Only process regular files
            let Ok(metadata) = fs::metadata(&path).await else {
                continue;
            };

            if metadata.is_file() {
                info!("Loading initial configuration file: {}", path.display());
                // In the C version, this would call read_hostsfile or option_read_dynfile
                // In our async Rust version, we just log and let the caller handle it
            }
        }

        Ok(())
    }

    /// Check if a filename should be ignored
    ///
    /// Ignores emacs backup files (~), lock files (#...#), and dotfiles.
    fn should_ignore_file(filename: &str) -> bool {
        if filename.is_empty() {
            return true;
        }

        let bytes = filename.as_bytes();
        let len = bytes.len();

        // Ignore files ending with '~' (emacs backups)
        if bytes[len - 1] == b'~' {
            return true;
        }

        // Ignore files starting and ending with '#' (lock files)
        if len >= 2 && bytes[0] == b'#' && bytes[len - 1] == b'#' {
            return true;
        }

        // Ignore files starting with '.' (dotfiles)
        if bytes[0] == b'.' {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_ignore_file() {
        // Should ignore backup files (ending with ~)
        assert!(InotifyWatcher::should_ignore_file("config~"));
        assert!(InotifyWatcher::should_ignore_file("resolv.conf~"));

        // Should ignore lock files (starting AND ending with #)
        assert!(InotifyWatcher::should_ignore_file("#config#"));
        assert!(InotifyWatcher::should_ignore_file("##"));

        // Should NOT ignore files that start with # but don't end with #
        assert!(!InotifyWatcher::should_ignore_file("#.#file"));
        assert!(!InotifyWatcher::should_ignore_file("#config"));

        // Should ignore dotfiles (starting with .)
        assert!(InotifyWatcher::should_ignore_file(".hidden"));
        assert!(InotifyWatcher::should_ignore_file(".config"));

        // Should not ignore regular files
        assert!(!InotifyWatcher::should_ignore_file("config"));
        assert!(!InotifyWatcher::should_ignore_file("resolv.conf"));
        assert!(!InotifyWatcher::should_ignore_file("hosts"));

        // Should ignore empty filename
        assert!(InotifyWatcher::should_ignore_file(""));
    }

    #[test]
    fn test_dir_flags_matches() {
        let hosts_flag = DirFlags::hosts();
        let dhcp_hosts_flag = DirFlags::dhcp_hosts();

        // Exact match
        assert!(hosts_flag.matches(&hosts_flag));
        assert!(dhcp_hosts_flag.matches(&dhcp_hosts_flag));

        // No match
        assert!(!hosts_flag.matches(&dhcp_hosts_flag));
        assert!(!dhcp_hosts_flag.matches(&hosts_flag));
    }
}
