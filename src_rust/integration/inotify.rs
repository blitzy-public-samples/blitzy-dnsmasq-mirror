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

//! Linux inotify integration for automatic configuration file monitoring
//!
//! # Overview
//!
//! This module provides Linux-specific inotify(7) API integration to enable automatic
//! monitoring of configuration files and directories. When configuration files change,
//! dnsmasq can automatically reload without requiring manual SIGHUP signals.
//!
//! # Purpose
//!
//! The inotify integration watches:
//! - resolv.conf files for DNS server updates
//! - Dynamic host directories (--hostsdir) for hosts file changes
//! - DHCP configuration directories (--dhcp-hostsdir, --dhcp-optsdir)
//!
//! File modifications, creations, or moves trigger automatic reloading, providing
//! seamless configuration updates for containerized and dynamic environments.
//!
//! # Strategy
//!
//! The implementation monitors **directories** containing configuration files, not the
//! files themselves. This handles files being replaced atomically (common with
//! configuration management tools like Puppet, Ansible, or Kubernetes ConfigMaps).
//! When directory events fire (IN_CLOSE_WRITE or IN_MOVED_TO), we check if the
//! affected file is actually a monitored configuration file, then trigger reload.
//!
//! # Symlink Handling
//!
//! The implementation follows symbolic links up to MAXSYMLINKS (20) depth to find
//! actual file locations. This is critical because:
//! - /etc/resolv.conf is often a symlink to /run/systemd/resolve/resolv.conf
//! - Configuration management tools may use symlinks for atomic updates
//! - Container environments frequently use symlink indirection
//!
//! # Error Handling
//!
//! All directories containing specified configuration files must exist at startup,
//! even if the actual files don't exist yet. Missing directories cause initialization
//! errors with detailed diagnostic messages.
//!
//! # Memory Safety
//!
//! This Rust implementation replaces C's manual inotify buffer management and pointer
//! arithmetic with type-safe abstractions:
//! - nix::sys::inotify for safe inotify API
//! - HashMap<WatchDescriptor, PathBuf> for O(1) event lookup (replaces linked lists)
//! - Vec<u8> for automatic buffer management
//! - std::path for safe path manipulation (eliminates buffer overflows)
//!
//! # Async Integration
//!
//! Uses tokio::io::unix::AsyncFd to integrate inotify file descriptor with the async
//! event loop, enabling non-blocking event processing without stalling DNS/DHCP
//! request handling.

use nix::fcntl::OFlag;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, InotifyEvent, WatchDescriptor};
use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::option::Option;
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::result::Result;
use std::sync::Arc;
use std::{fs, io};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task;
use tracing::{debug, error, info, trace, warn};

/// Maximum number of symbolic links to follow before giving up (prevents infinite loops)
const MAXSYMLINKS: u32 = 20;

/// Size of buffer for reading inotify events (struct inotify_event + NAME_MAX + 1)
/// NAME_MAX is typically 255, sizeof(struct inotify_event) is 16
const INOTIFY_BUFFER_SIZE: usize = 4096;

/// File event types that trigger configuration reloads
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileEventType {
    /// File was closed after being written (IN_CLOSE_WRITE)
    CloseWrite,
    /// File was moved into watched directory (IN_MOVED_TO)
    MovedTo,
    /// File was created in watched directory (IN_CREATE)
    Create,
    /// File was deleted from watched directory (IN_DELETE)
    Delete,
}

/// Event notification when a monitored file changes
#[derive(Debug, Clone)]
pub struct FileChangeEvent {
    /// Full path to the changed file
    pub path: PathBuf,
    /// Type of file system event that occurred
    pub event_type: FileEventType,
    /// Timestamp when event was detected (seconds since UNIX epoch)
    pub timestamp: u64,
}

impl FileChangeEvent {
    /// Create a new file change event
    fn new(path: PathBuf, event_type: FileEventType) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        FileChangeEvent {
            path,
            event_type,
            timestamp,
        }
    }
}

/// Errors that can occur during inotify operations
#[derive(Error, Debug)]
pub enum InotifyError {
    /// Failed to initialize inotify instance
    #[error("failed to create inotify: {source}")]
    InitFailed {
        #[source]
        source: nix::Error,
    },

    /// Failed to add watch for a specific path
    #[error("failed to create inotify for {path}: {source}")]
    AddWatchFailed {
        path: PathBuf,
        #[source]
        source: nix::Error,
    },

    /// Failed to remove an existing watch
    #[error("failed to remove inotify watch for descriptor {wd:?}: {source}")]
    RemoveWatchFailed {
        wd: WatchDescriptor,
        #[source]
        source: nix::Error,
    },

    /// Failed to read events from inotify file descriptor
    #[error("failed to read inotify events: {source}")]
    ReadEventsFailed {
        #[source]
        source: nix::Error,
    },

    /// Symbolic link chain exceeded MAXSYMLINKS depth
    #[error("too many symlinks following {path} (exceeded {max} depth)")]
    TooManySymlinks { path: PathBuf, max: u32 },

    /// Path is invalid (not a file or directory)
    #[error("invalid path {path}: {reason}")]
    InvalidPath { path: PathBuf, reason: String },

    /// Directory does not exist at specified path
    #[error("directory {path} for config file is missing, cannot monitor")]
    DirectoryNotFound { path: PathBuf },

    /// I/O error occurred during file operations
    #[error("I/O error: {0}")]
    Io(#[from] IoError),
}

/// Result type for inotify operations
pub type InotifyResult<T> = Result<T, InotifyError>;

/// Core inotify watcher for monitoring configuration files and directories
///
/// # Responsibilities
///
/// - Initialize inotify file descriptor with non-blocking mode
/// - Add watches for directories containing configuration files
/// - Track watch descriptors and associated paths
/// - Process inotify events and generate FileChangeEvent notifications
/// - Provide async event stream for integration with tokio event loop
///
/// # Watch Strategy
///
/// Watches are placed on **parent directories**, not individual files. This handles
/// the common pattern of atomic file replacement where:
/// 1. Tool writes new content to temporary file
/// 2. Tool renames temporary file to target filename (atomic operation)
/// 3. Old file is automatically replaced
///
/// Watching the directory catches both write-close events (direct modification) and
/// move-to events (atomic replacement).
///
/// # Thread Safety
///
/// InotifyWatcher is designed to be wrapped in Arc for safe sharing across async
/// tasks. The internal Inotify handle is not Sync, so we must ensure single-threaded
/// access or use appropriate synchronization.
pub struct InotifyWatcher {
    /// Inotify file descriptor handle
    inotify: Inotify,
    /// Map from watch descriptor to directory path being watched
    watches: HashMap<WatchDescriptor, PathBuf>,
    /// Map from watch descriptor to specific filenames within watched directories
    /// This allows us to filter events to only monitored files
    watch_files: HashMap<WatchDescriptor, Vec<String>>,
}

impl InotifyWatcher {
    /// Create a new inotify watcher instance
    ///
    /// Initializes inotify file descriptor with IN_NONBLOCK (non-blocking reads) and
    /// IN_CLOEXEC (close-on-exec flag for security).
    ///
    /// # Returns
    ///
    /// - `Ok(InotifyWatcher)` on successful initialization
    /// - `Err(InotifyError::InitFailed)` if inotify_init1 fails (e.g., resource limits)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::integration::inotify::InotifyWatcher;
    /// let watcher = InotifyWatcher::new()?;
    /// # Ok::<(), dnsmasq::integration::inotify::InotifyError>(())
    /// ```
    pub fn new() -> InotifyResult<Self> {
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)
            .map_err(|source| InotifyError::InitFailed { source })?;

        debug!("initialized inotify file descriptor");

        Ok(InotifyWatcher {
            inotify,
            watches: HashMap::new(),
            watch_files: HashMap::new(),
        })
    }

    /// Add a watch for a configuration file, following symlinks to find actual location
    ///
    /// This method follows the C implementation's strategy:
    /// 1. Follow symbolic link chain up to MAXSYMLINKS depth
    /// 2. Extract parent directory from resolved path
    /// 3. Add inotify watch on parent directory (not file itself)
    /// 4. Store filename for event filtering
    ///
    /// # Arguments
    ///
    /// * `path` - Path to configuration file (may be a symlink)
    ///
    /// # Returns
    ///
    /// - `Ok(WatchDescriptor)` on success
    /// - `Err(InotifyError::TooManySymlinks)` if symlink chain exceeds MAXSYMLINKS
    /// - `Err(InotifyError::DirectoryNotFound)` if parent directory doesn't exist
    /// - `Err(InotifyError::AddWatchFailed)` if inotify_add_watch fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::integration::inotify::InotifyWatcher;
    /// # use std::path::PathBuf;
    /// let mut watcher = InotifyWatcher::new()?;
    /// let wd = watcher.add_watch(PathBuf::from("/etc/resolv.conf"))?;
    /// # Ok::<(), dnsmasq::integration::inotify::InotifyError>(())
    /// ```
    pub fn add_watch(&mut self, path: PathBuf) -> InotifyResult<WatchDescriptor> {
        // Follow symlinks to find actual file location
        let resolved_path = self.resolve_symlinks(&path)?;

        trace!(
            "resolved path {} to {}",
            path.display(),
            resolved_path.display()
        );

        // Extract parent directory and filename
        let (dir_path, filename) = match resolved_path.parent() {
            Some(parent) => {
                let fname = resolved_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| InotifyError::InvalidPath {
                        path: resolved_path.clone(),
                        reason: "no filename component".to_string(),
                    })?;
                (parent.to_path_buf(), fname.to_string())
            }
            None => {
                return Err(InotifyError::InvalidPath {
                    path: resolved_path,
                    reason: "no parent directory".to_string(),
                })
            }
        };

        // Verify directory exists
        if !dir_path.exists() {
            return Err(InotifyError::DirectoryNotFound { path: dir_path });
        }

        // Add watch for directory with IN_CLOSE_WRITE and IN_MOVED_TO events
        let flags = AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_MOVED_TO;
        let wd = self
            .inotify
            .add_watch(&dir_path, flags)
            .map_err(|source| InotifyError::AddWatchFailed {
                path: dir_path.clone(),
                source,
            })?;

        debug!(
            "added inotify watch for directory {} (filename: {}, wd: {:?})",
            dir_path.display(),
            filename,
            wd
        );

        // Store watch descriptor mapping
        self.watches.insert(wd, dir_path);
        self.watch_files
            .entry(wd)
            .or_insert_with(Vec::new)
            .push(filename);

        Ok(wd)
    }

    /// Add a watch for a dynamic directory containing multiple configuration files
    ///
    /// Monitors entire directory for file changes, filtering out backup files,
    /// dotfiles, and temporary files.
    ///
    /// # Arguments
    ///
    /// * `dir_path` - Path to directory to monitor
    ///
    /// # Returns
    ///
    /// - `Ok(WatchDescriptor)` on success
    /// - `Err(InotifyError::InvalidPath)` if path is not a directory
    /// - `Err(InotifyError::AddWatchFailed)` if watch creation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::integration::inotify::InotifyWatcher;
    /// # use std::path::PathBuf;
    /// let mut watcher = InotifyWatcher::new()?;
    /// let wd = watcher.add_directory_watch(PathBuf::from("/etc/dnsmasq.d/hosts"))?;
    /// # Ok::<(), dnsmasq::integration::inotify::InotifyError>(())
    /// ```
    pub fn add_directory_watch(&mut self, dir_path: PathBuf) -> InotifyResult<WatchDescriptor> {
        // Validate path is a directory
        let metadata = fs::metadata(&dir_path)?;
        if !metadata.is_dir() {
            return Err(InotifyError::InvalidPath {
                path: dir_path,
                reason: "not a directory".to_string(),
            });
        }

        // Add watch for directory
        let flags = AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_MOVED_TO;
        let wd = self
            .inotify
            .add_watch(&dir_path, flags)
            .map_err(|source| InotifyError::AddWatchFailed {
                path: dir_path.clone(),
                source,
            })?;

        debug!(
            "added inotify watch for directory {} (wd: {:?})",
            dir_path.display(),
            wd
        );

        // Store watch descriptor mapping (no specific filenames for directory watches)
        self.watches.insert(wd, dir_path);

        Ok(wd)
    }

    /// Remove an existing inotify watch
    ///
    /// # Arguments
    ///
    /// * `wd` - Watch descriptor to remove
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(InotifyError::RemoveWatchFailed)` if removal fails
    pub fn remove_watch(&mut self, wd: WatchDescriptor) -> InotifyResult<()> {
        self.inotify
            .rm_watch(wd)
            .map_err(|source| InotifyError::RemoveWatchFailed { wd, source })?;

        self.watches.remove(&wd);
        self.watch_files.remove(&wd);

        debug!("removed inotify watch descriptor {:?}", wd);

        Ok(())
    }

    /// Process pending inotify events and generate file change notifications
    ///
    /// Reads all available events from inotify file descriptor (non-blocking) and
    /// generates FileChangeEvent for each relevant file change. Filters out:
    /// - Emacs backup files (ending with ~)
    /// - Lock files (#file#)
    /// - Dotfiles (starting with .)
    /// - Events for non-monitored files in watched directories
    ///
    /// # Returns
    ///
    /// Vector of FileChangeEvent notifications for configuration file changes.
    /// Empty vector if no relevant events occurred or EAGAIN/EWOULDBLOCK on read.
    ///
    /// # Errors
    ///
    /// Returns `Err(InotifyError::ReadEventsFailed)` on read errors other than
    /// EAGAIN/EWOULDBLOCK.
    pub fn process_events(&mut self) -> InotifyResult<Vec<FileChangeEvent>> {
        let mut events = Vec::new();

        // Read events from inotify file descriptor
        let inotify_events = match self.inotify.read_events() {
            Ok(evts) => evts,
            Err(nix::Error::EAGAIN) => {
                // No events available (non-blocking mode)
                return Ok(events);
            }
            Err(source) => {
                return Err(InotifyError::ReadEventsFailed { source });
            }
        };

        // Process each event
        for event in inotify_events {
            if let Some(change_event) = self.process_single_event(event) {
                events.push(change_event);
            }
        }

        Ok(events)
    }

    /// Process a single inotify event and generate FileChangeEvent if relevant
    ///
    /// Internal helper for process_events(). Applies filtering logic to ignore
    /// backup files, temporary files, and non-monitored files.
    fn process_single_event(&self, event: InotifyEvent) -> Option<FileChangeEvent> {
        let wd = event.wd;
        let name = event.name?;
        let filename = name.to_str()?;

        // Ignore zero-length names
        if filename.is_empty() {
            return None;
        }

        // Ignore emacs backup files (ending with ~)
        if filename.ends_with('~') {
            trace!("ignoring emacs backup file: {}", filename);
            return None;
        }

        // Ignore lock files (#file#)
        if filename.starts_with('#') && filename.ends_with('#') {
            trace!("ignoring lock file: {}", filename);
            return None;
        }

        // Ignore dotfiles (starting with .)
        if filename.starts_with('.') {
            trace!("ignoring dotfile: {}", filename);
            return None;
        }

        // Check if this watch descriptor is for a specific file or directory
        let dir_path = self.watches.get(&wd)?;

        // If we have specific filenames registered for this watch, filter to only those
        if let Some(watched_files) = self.watch_files.get(&wd) {
            if !watched_files.is_empty() && !watched_files.contains(&filename.to_string()) {
                trace!(
                    "ignoring event for non-monitored file: {} in {}",
                    filename,
                    dir_path.display()
                );
                return None;
            }
        }

        // Construct full path to changed file
        let full_path = dir_path.join(filename);

        // Determine event type from inotify mask
        let event_type = if event.mask.contains(AddWatchFlags::IN_CLOSE_WRITE) {
            FileEventType::CloseWrite
        } else if event.mask.contains(AddWatchFlags::IN_MOVED_TO) {
            FileEventType::MovedTo
        } else if event.mask.contains(AddWatchFlags::IN_CREATE) {
            FileEventType::Create
        } else if event.mask.contains(AddWatchFlags::IN_DELETE) {
            FileEventType::Delete
        } else {
            // Unknown or unhandled event type
            return None;
        };

        info!(
            "inotify: new or changed file {} (type: {:?})",
            full_path.display(),
            event_type
        );

        Some(FileChangeEvent::new(full_path, event_type))
    }

    /// Create an async event stream for integration with tokio event loop
    ///
    /// Returns a channel receiver that yields FileChangeEvent notifications as
    /// configuration files change. A background task monitors the inotify file
    /// descriptor and sends events through the channel.
    ///
    /// # Returns
    ///
    /// Receiver<FileChangeEvent> that yields file change notifications
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::integration::inotify::InotifyWatcher;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut watcher = InotifyWatcher::new()?;
    /// let mut event_stream = watcher.event_stream();
    ///
    /// while let Some(event) = event_stream.recv().await {
    ///     println!("File changed: {}", event.path.display());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn event_stream(self) -> Receiver<FileChangeEvent> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        // Spawn async task to monitor inotify fd
        task::spawn(async move {
            if let Err(e) = Self::event_loop(self, tx).await {
                error!("inotify event loop error: {}", e);
            }
        });

        rx
    }

    /// Async event loop that monitors inotify file descriptor and sends events
    ///
    /// Internal helper for event_stream(). Wraps inotify fd in AsyncFd for async
    /// I/O integration with tokio, processes events when fd becomes readable.
    async fn event_loop(
        mut watcher: InotifyWatcher,
        tx: Sender<FileChangeEvent>,
    ) -> InotifyResult<()> {
        // Get raw file descriptor from inotify handle
        // SAFETY: We maintain exclusive ownership of the inotify fd
        let fd = watcher.inotify.as_fd().as_raw_fd();
        let async_fd = AsyncFd::new(fd)
            .map_err(|e| InotifyError::Io(io::Error::new(ErrorKind::Other, e)))?;

        loop {
            // Wait for inotify fd to become readable
            let mut guard = async_fd
                .readable()
                .await
                .map_err(|e| InotifyError::Io(io::Error::new(ErrorKind::Other, e)))?;

            // Process events
            match watcher.process_events() {
                Ok(events) => {
                    for event in events {
                        if tx.send(event).await.is_err() {
                            // Receiver dropped, exit event loop
                            return Ok(());
                        }
                    }
                    guard.clear_ready();
                }
                Err(InotifyError::ReadEventsFailed {
                    source: nix::Error::EAGAIN,
                }) => {
                    // No events available, wait for next readable notification
                    guard.clear_ready();
                }
                Err(e) => {
                    // Propagate error
                    return Err(e);
                }
            }
        }
    }

    /// Resolve symbolic links to find actual file location
    ///
    /// Follows symlink chain up to MAXSYMLINKS depth to prevent infinite loops.
    /// Converts relative symlink targets to absolute paths by prepending parent
    /// directory path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path that may contain symbolic links
    ///
    /// # Returns
    ///
    /// - `Ok(PathBuf)` with resolved absolute path
    /// - `Err(InotifyError::TooManySymlinks)` if chain exceeds MAXSYMLINKS
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use dnsmasq::integration::inotify::InotifyWatcher;
    /// # use std::path::PathBuf;
    /// let watcher = InotifyWatcher::new()?;
    /// let resolved = watcher.resolve_symlinks(&PathBuf::from("/etc/resolv.conf"))?;
    /// # Ok::<(), dnsmasq::integration::inotify::InotifyError>(())
    /// ```
    fn resolve_symlinks(&self, path: &Path) -> InotifyResult<PathBuf> {
        let mut current_path = path.to_path_buf();
        let mut links_followed = 0;

        loop {
            // Try to read symlink
            match fs::read_link(&current_path) {
                Ok(target) => {
                    links_followed += 1;
                    if links_followed > MAXSYMLINKS {
                        return Err(InotifyError::TooManySymlinks {
                            path: path.to_path_buf(),
                            max: MAXSYMLINKS,
                        });
                    }

                    // Convert relative paths to absolute
                    let resolved_target = if target.is_absolute() {
                        target
                    } else {
                        // Prepend parent directory of current_path
                        if let Some(parent) = current_path.parent() {
                            parent.join(target)
                        } else {
                            target
                        }
                    };

                    trace!(
                        "followed symlink {} -> {}",
                        current_path.display(),
                        resolved_target.display()
                    );

                    current_path = resolved_target;
                }
                Err(e) if e.kind() == ErrorKind::InvalidInput => {
                    // Not a symlink (EINVAL), return current path
                    return Ok(current_path);
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    // File doesn't exist yet (ENOENT), return current path (watch will be on directory)
                    return Ok(current_path);
                }
                Err(e) => {
                    // Unexpected error
                    return Err(InotifyError::Io(e));
                }
            }
        }
    }

    /// Get the raw inotify file descriptor for direct manipulation if needed
    ///
    /// Exposed for advanced use cases that need to integrate inotify fd with
    /// custom event loops or polling mechanisms.
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.inotify.as_fd().as_raw_fd()
    }
}

/// High-level convenience function to watch configuration files
///
/// Sets up inotify watches for a list of configuration file paths, returning
/// an InotifyWatcher instance ready for event processing.
///
/// # Arguments
///
/// * `paths` - Iterator of paths to configuration files (may include symlinks)
///
/// # Returns
///
/// - `Ok(InotifyWatcher)` with all watches configured
/// - `Err(InotifyError)` if initialization or watch creation fails
///
/// # Example
///
/// ```no_run
/// # use dnsmasq::integration::inotify::watch_config_files;
/// # use std::path::PathBuf;
/// let paths = vec![
///     PathBuf::from("/etc/resolv.conf"),
///     PathBuf::from("/etc/dnsmasq.conf"),
/// ];
/// let watcher = watch_config_files(paths.iter())?;
/// # Ok::<(), dnsmasq::integration::inotify::InotifyError>(())
/// ```
pub fn watch_config_files<'a, I>(paths: I) -> InotifyResult<InotifyWatcher>
where
    I: Iterator<Item = &'a PathBuf>,
{
    let mut watcher = InotifyWatcher::new()?;

    for path in paths {
        match watcher.add_watch(path.clone()) {
            Ok(wd) => {
                info!("monitoring configuration file: {} (wd: {:?})", path.display(), wd);
            }
            Err(e) => {
                error!("failed to watch {}: {}", path.display(), e);
                return Err(e);
            }
        }
    }

    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_inotify_watcher_new() {
        let result = InotifyWatcher::new();
        assert!(result.is_ok(), "should create inotify watcher");
    }

    #[test]
    fn test_add_watch_nonexistent_directory() {
        let mut watcher = InotifyWatcher::new().unwrap();
        let path = PathBuf::from("/nonexistent/path/file.conf");

        let result = watcher.add_watch(path);
        assert!(
            matches!(result, Err(InotifyError::DirectoryNotFound { .. })),
            "should fail for nonexistent directory"
        );
    }

    #[test]
    fn test_add_directory_watch_invalid_path() {
        let mut watcher = InotifyWatcher::new().unwrap();
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("not_a_dir");
        File::create(&file_path).unwrap();

        let result = watcher.add_directory_watch(file_path);
        assert!(
            matches!(result, Err(InotifyError::InvalidPath { .. })),
            "should fail for non-directory path"
        );
    }

    #[test]
    fn test_resolve_symlinks_absolute() {
        let watcher = InotifyWatcher::new().unwrap();
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("real_file");
        File::create(&file_path).unwrap();

        let result = watcher.resolve_symlinks(&file_path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), file_path);
    }

    #[test]
    fn test_file_event_type_equality() {
        assert_eq!(FileEventType::CloseWrite, FileEventType::CloseWrite);
        assert_ne!(FileEventType::CloseWrite, FileEventType::MovedTo);
    }

    #[test]
    fn test_file_change_event_creation() {
        let path = PathBuf::from("/etc/test.conf");
        let event = FileChangeEvent::new(path.clone(), FileEventType::CloseWrite);

        assert_eq!(event.path, path);
        assert_eq!(event.event_type, FileEventType::CloseWrite);
        assert!(event.timestamp > 0);
    }
}
