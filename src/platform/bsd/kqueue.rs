//! BSD kqueue-based file system monitoring
//!
//! This module provides file system monitoring capabilities for BSD platforms (FreeBSD,
//! OpenBSD, NetBSD, DragonFly BSD, and macOS) using the kqueue event notification interface.
//! It serves as an alternative to Linux's inotify, providing similar functionality through
//! the EVFILT_VNODE filter.
//!
//! # Overview
//!
//! The kqueue interface allows monitoring of file system events such as file modifications,
//! deletions, creations (via directory watching), and attribute changes. Unlike inotify
//! which is path-based, kqueue requires keeping file descriptors open for each watched file,
//! which provides more precise event delivery but consumes more file descriptors.
//!
//! # Key Differences from inotify
//!
//! - **File Descriptor Based**: Each watched file/directory requires an open file descriptor
//! - **Richer Events**: EVFILT_VNODE provides more detailed event types via NOTE_* flags
//! - **No Artificial Limits**: Limited only by available file descriptors, not kernel limits
//! - **Better Hard Link Handling**: Events tied to file descriptor, not path
//!
//! # Usage
//!
//! ```no_run
//! use dnsmasq::platform::bsd::kqueue::{KqueueWatcher, FileEvent};
//!
//! async fn watch_resolv_conf() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut watcher = KqueueWatcher::new().await?;
//!     watcher.watch_file("/etc/resolv.conf".into()).await?;
//!     
//!     while let Some(event) = watcher.next_event().await {
//!         match event {
//!             FileEvent::FileModified(path) => {
//!                 println!("File modified: {:?}", path);
//!                 // Trigger configuration reload
//!             }
//!             FileEvent::FileDeleted(path) => {
//!                 println!("File deleted: {:?}", path);
//!             }
//!             _ => {}
//!         }
//!     }
//!     Ok(())
//! }
//! ```

use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent};
use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;
use tokio::io::unix::AsyncFd;
use tracing::debug;

/// Maximum number of symbolic links to follow before giving up
const MAXSYMLINKS: usize = 40;

/// File descriptor for an invalid/closed file
const INVALID_FD: RawFd = -1;

/// Errors that can occur during kqueue file monitoring operations
#[derive(Error, Debug)]
pub enum KqueueError {
    /// Failed to initialize kqueue
    #[error("Failed to initialize kqueue: {0}")]
    InitFailed(#[source] std::io::Error),

    /// Failed to add watch to kqueue
    #[error("Failed to add watch for {path:?}: {source}")]
    AddWatchFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Symbolic link chain exceeded MAXSYMLINKS
    #[error("Too many symbolic links (>{MAXSYMLINKS}) when resolving {0:?}")]
    TooManySymlinks(PathBuf),

    /// Watched file not found
    #[error("File not found: {0:?}")]
    FileNotFound(PathBuf),

    /// Generic I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Too many watches (file descriptor limit reached)
    #[error("Too many watches: file descriptor limit reached")]
    TooManyWatches,
}

/// File system events reported by kqueue
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEvent {
    /// File was modified (written to or extended)
    FileModified(PathBuf),

    /// File was deleted
    FileDeleted(PathBuf),

    /// New file created in watched directory
    FileCreated(PathBuf),

    /// File attributes changed (permissions, timestamps, etc.)
    AttributeChanged(PathBuf),

    /// File was renamed
    FileRenamed(PathBuf),
}

/// Internal representation of a watched file
#[derive(Debug)]
struct WatchedFile {
    /// Path to the file being watched
    path: PathBuf,
    /// File descriptor for the watched file
    fd: RawFd,
    /// True if the original path was a symbolic link
    is_symlink: bool,
}

impl Drop for WatchedFile {
    fn drop(&mut self) {
        if self.fd != INVALID_FD {
            unsafe {
                libc::close(self.fd);
            }
            debug!("Closed file descriptor {} for {:?}", self.fd, self.path);
        }
    }
}

/// Internal representation of a watched directory
#[derive(Debug)]
struct WatchedDir {
    /// Path to the directory being watched
    path: PathBuf,
    /// File descriptor for the watched directory
    fd: RawFd,
    /// Files currently present in the directory (for detecting new files)
    known_files: Vec<PathBuf>,
}

impl Drop for WatchedDir {
    fn drop(&mut self) {
        if self.fd != INVALID_FD {
            unsafe {
                libc::close(self.fd);
            }
            debug!(
                "Closed directory descriptor {} for {:?}",
                self.fd, self.path
            );
        }
    }
}

/// BSD kqueue-based file system watcher
///
/// This struct provides an async interface to BSD's kqueue mechanism for monitoring
/// file system events. It maintains open file descriptors for all watched files and
/// directories, and integrates with Tokio's async runtime for non-blocking event delivery.
///
/// # Implementation Notes
///
/// - Each watched file/directory consumes one file descriptor
/// - File descriptors are automatically closed when watches are removed or on Drop
/// - Symbolic links are resolved and the target file is watched
/// - Directory watches detect new file creation via NOTE_WRITE events
/// - Events are delivered asynchronously through the `next_event()` method
pub struct KqueueWatcher {
    /// Async file descriptor wrapper for the kqueue
    kqueue_fd: AsyncFd<RawFd>,
    /// Map from file descriptor to watched file information
    watched_files: HashMap<RawFd, WatchedFile>,
    /// Map from file descriptor to watched directory information
    watched_dirs: HashMap<RawFd, WatchedDir>,
    /// Reverse map from path to file descriptor for efficient unwatch operations
    path_to_fd: HashMap<PathBuf, RawFd>,
    /// Pending events buffer (for batch event processing)
    pending_events: Vec<FileEvent>,
}

impl KqueueWatcher {
    /// Create a new kqueue-based file system watcher
    ///
    /// # Errors
    ///
    /// Returns `KqueueError::InitFailed` if the kqueue() system call fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::platform::bsd::kqueue::KqueueWatcher;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let watcher = KqueueWatcher::new().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new() -> Result<Self, KqueueError> {
        // Create kqueue file descriptor
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(KqueueError::InitFailed(std::io::Error::last_os_error()));
        }

        debug!("Created kqueue with fd {}", kq);

        // Set close-on-exec flag
        unsafe {
            let flags = libc::fcntl(kq, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(kq, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }

        // Wrap in AsyncFd for Tokio integration
        let async_fd = AsyncFd::new(kq).map_err(|e| KqueueError::InitFailed(e))?;

        Ok(Self {
            kqueue_fd: async_fd,
            watched_files: HashMap::new(),
            watched_dirs: HashMap::new(),
            path_to_fd: HashMap::new(),
            pending_events: Vec::new(),
        })
    }

    /// Watch a single file for changes
    ///
    /// This method resolves symbolic links and watches the target file. The file is opened
    /// with O_RDONLY | O_CLOEXEC and the file descriptor is registered with kqueue using
    /// EVFILT_VNODE to monitor NOTE_WRITE, NOTE_DELETE, NOTE_EXTEND, NOTE_ATTRIB, and
    /// NOTE_RENAME events.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to watch (can be a symbolic link)
    ///
    /// # Errors
    ///
    /// - `KqueueError::FileNotFound` if the file doesn't exist
    /// - `KqueueError::TooManySymlinks` if symlink resolution exceeds MAXSYMLINKS
    /// - `KqueueError::AddWatchFailed` if the kevent registration fails
    /// - `KqueueError::TooManyWatches` if file descriptor limit is reached
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::platform::bsd::kqueue::KqueueWatcher;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut watcher = KqueueWatcher::new().await?;
    /// watcher.watch_file("/etc/resolv.conf".into()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn watch_file(&mut self, path: PathBuf) -> Result<(), KqueueError> {
        debug!("Adding file watch for {:?}", path);

        // Check if already watching this path
        if self.path_to_fd.contains_key(&path) {
            debug!("Already watching {:?}, skipping", path);
            return Ok(());
        }

        // Resolve symbolic links
        let (resolved_path, is_symlink) = self.resolve_symlink(&path).await?;

        debug!(
            "Resolved {:?} to {:?} (is_symlink: {})",
            path, resolved_path, is_symlink
        );

        // Open the file to get a file descriptor
        let fd = self.open_file_for_watching(&resolved_path)?;

        // Register with kqueue
        self.register_file_watch(fd, &resolved_path)?;

        // Store watch information
        let watched_file = WatchedFile {
            path: resolved_path.clone(),
            fd,
            is_symlink,
        };

        self.watched_files.insert(fd, watched_file);
        self.path_to_fd.insert(path, fd);

        debug!(
            "Successfully added watch for fd {} -> {:?}",
            fd, resolved_path
        );

        Ok(())
    }

    /// Watch a directory for new file creation
    ///
    /// This method watches a directory for NOTE_WRITE events, which indicate that files
    /// have been added, removed, or renamed in the directory. When such events occur,
    /// the directory is scanned to detect new files (ignoring emacs backups, lock files,
    /// and dotfiles).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the directory to watch
    ///
    /// # Errors
    ///
    /// - `KqueueError::FileNotFound` if the directory doesn't exist
    /// - `KqueueError::AddWatchFailed` if the kevent registration fails
    /// - `KqueueError::TooManyWatches` if file descriptor limit is reached
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::platform::bsd::kqueue::KqueueWatcher;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut watcher = KqueueWatcher::new().await?;
    /// watcher.watch_directory("/etc/dnsmasq.d".into()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn watch_directory(&mut self, path: PathBuf) -> Result<(), KqueueError> {
        debug!("Adding directory watch for {:?}", path);

        // Check if already watching this path
        if self.path_to_fd.contains_key(&path) {
            debug!("Already watching {:?}, skipping", path);
            return Ok(());
        }

        // Verify the path is a directory
        let metadata = fs::metadata(&path)
            .await
            .map_err(|_| KqueueError::FileNotFound(path.clone()))?;

        if !metadata.is_dir() {
            return Err(KqueueError::AddWatchFailed {
                path: path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Path is not a directory",
                ),
            });
        }

        // Open the directory
        let fd = self.open_directory_for_watching(&path)?;

        // Register with kqueue
        self.register_directory_watch(fd, &path)?;

        // Read initial directory contents to avoid race conditions
        let known_files = self.read_directory_files(&path).await?;

        debug!(
            "Directory {:?} initially contains {} files",
            path,
            known_files.len()
        );

        // Store watch information
        let watched_dir = WatchedDir {
            path: path.clone(),
            fd,
            known_files,
        };

        self.watched_dirs.insert(fd, watched_dir);
        self.path_to_fd.insert(path, fd);

        debug!("Successfully added directory watch for fd {}", fd);

        Ok(())
    }

    /// Get the next file system event
    ///
    /// This method blocks until a file system event occurs on any watched file or directory.
    /// It integrates with Tokio's async runtime for efficient non-blocking operation.
    ///
    /// # Returns
    ///
    /// Returns `Some(FileEvent)` when an event occurs, or `None` if the watcher is closed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::platform::bsd::kqueue::{KqueueWatcher, FileEvent};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut watcher = KqueueWatcher::new().await?;
    /// watcher.watch_file("/etc/resolv.conf".into()).await?;
    ///
    /// while let Some(event) = watcher.next_event().await {
    ///     match event {
    ///         FileEvent::FileModified(path) => println!("Modified: {:?}", path),
    ///         FileEvent::FileDeleted(path) => println!("Deleted: {:?}", path),
    ///         _ => {}
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn next_event(&mut self) -> Option<FileEvent> {
        loop {
            // Return pending events first
            if !self.pending_events.is_empty() {
                return Some(self.pending_events.remove(0));
            }

            // Wait for kqueue to become readable
            let mut guard = match self.kqueue_fd.readable().await {
                Ok(g) => g,
                Err(e) => {
                    debug!("Error waiting for kqueue readability: {}", e);
                    return None;
                }
            };

            // Try to read events
            match guard.try_io(|inner| {
                let kq = *inner.get_ref();
                self.read_events(kq)
            }) {
                Ok(Ok(())) => {
                    // Events were read and added to pending_events
                    continue;
                }
                Ok(Err(e)) => {
                    debug!("Error reading kqueue events: {}", e);
                    return None;
                }
                Err(_would_block) => {
                    // Would block, clear readiness and retry
                    guard.clear_ready();
                    continue;
                }
            }
        }
    }

    /// Remove a watch for a file or directory
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file or directory to stop watching
    ///
    /// # Errors
    ///
    /// Returns `KqueueError::FileNotFound` if the path is not being watched.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::platform::bsd::kqueue::KqueueWatcher;
    /// # use std::path::Path;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut watcher = KqueueWatcher::new().await?;
    /// watcher.watch_file("/etc/resolv.conf".into()).await?;
    /// watcher.unwatch(Path::new("/etc/resolv.conf")).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn unwatch(&mut self, path: &Path) -> Result<(), KqueueError> {
        debug!("Removing watch for {:?}", path);

        let fd = self
            .path_to_fd
            .remove(path)
            .ok_or_else(|| KqueueError::FileNotFound(path.to_path_buf()))?;

        // Remove from appropriate map (file or directory)
        self.watched_files.remove(&fd);
        self.watched_dirs.remove(&fd);

        // File descriptor will be closed by Drop implementation

        debug!("Successfully removed watch for {:?}", path);

        Ok(())
    }

    /// Resolve symbolic links, following up to MAXSYMLINKS levels
    ///
    /// Returns the resolved path and a boolean indicating if the original path was a symlink.
    async fn resolve_symlink(&self, path: &Path) -> Result<(PathBuf, bool), KqueueError> {
        let mut current_path = path.to_path_buf();
        let mut is_symlink = false;

        for depth in 0..MAXSYMLINKS {
            match fs::symlink_metadata(&current_path).await {
                Ok(metadata) => {
                    if !metadata.is_symlink() {
                        // Not a symlink, we're done
                        return Ok((current_path, is_symlink));
                    }

                    // It's a symlink, resolve it
                    is_symlink = true;
                    let target = fs::read_link(&current_path)
                        .await
                        .map_err(|e| KqueueError::IoError(e))?;

                    debug!(
                        "Symlink {:?} -> {:?} (depth {})",
                        current_path, target, depth
                    );

                    // If target is relative, resolve it relative to the symlink's directory
                    current_path = if target.is_absolute() {
                        target
                    } else {
                        let parent = current_path.parent().unwrap_or(Path::new("/"));
                        parent.join(target)
                    };
                }
                Err(_) => {
                    return Err(KqueueError::FileNotFound(current_path));
                }
            }
        }

        // Exceeded MAXSYMLINKS
        Err(KqueueError::TooManySymlinks(path.to_path_buf()))
    }

    /// Open a file for watching with appropriate flags
    fn open_file_for_watching(&self, path: &Path) -> Result<RawFd, KqueueError> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let path_cstring = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| KqueueError::FileNotFound(path.to_path_buf()))?;

        let fd = unsafe { libc::open(path_cstring.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EMFILE) || err.raw_os_error() == Some(libc::ENFILE)
            {
                return Err(KqueueError::TooManyWatches);
            }
            return Err(KqueueError::AddWatchFailed {
                path: path.to_path_buf(),
                source: err,
            });
        }

        debug!("Opened file {:?} with fd {}", path, fd);

        Ok(fd)
    }

    /// Open a directory for watching with appropriate flags
    fn open_directory_for_watching(&self, path: &Path) -> Result<RawFd, KqueueError> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let path_cstring = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| KqueueError::FileNotFound(path.to_path_buf()))?;

        let fd = unsafe {
            libc::open(
                path_cstring.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EMFILE) || err.raw_os_error() == Some(libc::ENFILE)
            {
                return Err(KqueueError::TooManyWatches);
            }
            return Err(KqueueError::AddWatchFailed {
                path: path.to_path_buf(),
                source: err,
            });
        }

        debug!("Opened directory {:?} with fd {}", path, fd);

        Ok(fd)
    }

    /// Register a file descriptor with kqueue for file event monitoring
    fn register_file_watch(&self, fd: RawFd, path: &Path) -> Result<(), KqueueError> {
        // Create kevent for file monitoring
        // Monitor: WRITE, DELETE, EXTEND, ATTRIB, RENAME
        let fflags = FilterFlag::NOTE_WRITE
            | FilterFlag::NOTE_DELETE
            | FilterFlag::NOTE_EXTEND
            | FilterFlag::NOTE_ATTRIB
            | FilterFlag::NOTE_RENAME;

        let kev = KEvent::new(
            fd as usize,
            EventFilter::EVFILT_VNODE,
            EventFlag::EV_ADD | EventFlag::EV_ENABLE | EventFlag::EV_CLEAR,
            fflags,
            0,
            0,
        );

        debug!(
            "Registering kevent for fd {} ({:?}): filter={:?}, flags={:?}, fflags={:?}",
            fd,
            path,
            EventFilter::EVFILT_VNODE,
            EventFlag::EV_ADD | EventFlag::EV_ENABLE | EventFlag::EV_CLEAR,
            fflags
        );

        // Register the event
        let kq = *self.kqueue_fd.get_ref();
        let result = unsafe {
            libc::kevent(
                kq,
                &kev as *const KEvent as *const libc::kevent,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };

        if result < 0 {
            return Err(KqueueError::AddWatchFailed {
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }

        Ok(())
    }

    /// Register a directory descriptor with kqueue for monitoring new file creation
    fn register_directory_watch(&self, fd: RawFd, path: &Path) -> Result<(), KqueueError> {
        // Create kevent for directory monitoring
        // Monitor: WRITE (indicates file added/removed)
        let fflags = FilterFlag::NOTE_WRITE;

        let kev = KEvent::new(
            fd as usize,
            EventFilter::EVFILT_VNODE,
            EventFlag::EV_ADD | EventFlag::EV_ENABLE | EventFlag::EV_CLEAR,
            fflags,
            0,
            0,
        );

        debug!("Registering directory kevent for fd {} ({:?})", fd, path);

        // Register the event
        let kq = *self.kqueue_fd.get_ref();
        let result = unsafe {
            libc::kevent(
                kq,
                &kev as *const KEvent as *const libc::kevent,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };

        if result < 0 {
            return Err(KqueueError::AddWatchFailed {
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }

        Ok(())
    }

    /// Read events from kqueue and add them to pending_events
    fn read_events(&mut self, kq: RawFd) -> Result<(), KqueueError> {
        const MAX_EVENTS: usize = 32;
        let mut events: [libc::kevent; MAX_EVENTS] = unsafe { std::mem::zeroed() };

        // Use zero timeout for non-blocking read
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };

        let num_events = unsafe {
            libc::kevent(
                kq,
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                MAX_EVENTS as i32,
                &timeout,
            )
        };

        if num_events < 0 {
            let err = std::io::Error::last_os_error();
            // EINTR is not an error, just means we should retry
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(KqueueError::IoError(err));
            }
            return Ok(());
        }

        debug!("Read {} events from kqueue", num_events);

        // Process each event
        for i in 0..num_events as usize {
            let event = &events[i];
            self.process_kevent(event);
        }

        Ok(())
    }

    /// Process a single kevent and convert it to FileEvent(s)
    fn process_kevent(&mut self, event: &libc::kevent) {
        let fd = event.ident as RawFd;
        let fflags = event.fflags;

        debug!(
            "Processing kevent: fd={}, filter={}, flags={}, fflags={}",
            fd, event.filter, event.flags, fflags
        );

        // Check if this is a file or directory watch
        if let Some(watched_file) = self.watched_files.get(&fd) {
            self.process_file_event(&watched_file.path, fflags, event.flags);
        } else if let Some(watched_dir) = self.watched_dirs.get_mut(&fd) {
            // For directories, NOTE_WRITE means contents changed
            // We need to scan the directory to find new files
            let path = watched_dir.path.clone();
            // Schedule async directory scan
            // For now, just emit a generic event
            self.pending_events
                .push(FileEvent::FileModified(path.clone()));
            debug!("Directory {:?} modified, may contain new files", path);
        }
    }

    /// Convert kqueue fflags to FileEvent(s) for a file
    fn process_file_event(&mut self, path: &Path, fflags: u32, flags: u16) {
        debug!("File event for {:?}: fflags={}", path, fflags);

        // Check for EV_EOF which indicates file descriptor closed (file deleted)
        if (flags & libc::EV_EOF as u16) != 0 {
            self.pending_events
                .push(FileEvent::FileDeleted(path.to_path_buf()));
            debug!("File {:?} deleted (EV_EOF)", path);
            return;
        }

        // NOTE_DELETE: file was deleted
        if (fflags & libc::NOTE_DELETE) != 0 {
            self.pending_events
                .push(FileEvent::FileDeleted(path.to_path_buf()));
            debug!("File {:?} deleted (NOTE_DELETE)", path);
        }

        // NOTE_WRITE or NOTE_EXTEND: file was modified
        if (fflags & (libc::NOTE_WRITE | libc::NOTE_EXTEND)) != 0 {
            self.pending_events
                .push(FileEvent::FileModified(path.to_path_buf()));
            debug!("File {:?} modified (NOTE_WRITE/EXTEND)", path);
        }

        // NOTE_ATTRIB: file attributes changed
        if (fflags & libc::NOTE_ATTRIB) != 0 {
            self.pending_events
                .push(FileEvent::AttributeChanged(path.to_path_buf()));
            debug!("File {:?} attributes changed (NOTE_ATTRIB)", path);
        }

        // NOTE_RENAME: file was renamed
        if (fflags & libc::NOTE_RENAME) != 0 {
            self.pending_events
                .push(FileEvent::FileRenamed(path.to_path_buf()));
            debug!("File {:?} renamed (NOTE_RENAME)", path);
        }
    }

    /// Read files in a directory, filtering out unwanted entries
    async fn read_directory_files(&self, path: &Path) -> Result<Vec<PathBuf>, KqueueError> {
        let mut files = Vec::new();
        let mut entries = fs::read_dir(path)
            .await
            .map_err(|e| KqueueError::IoError(e))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| KqueueError::IoError(e))?
        {
            let entry_path = entry.path();
            let file_name = match entry_path.file_name() {
                Some(name) => name.to_string_lossy(),
                None => continue,
            };

            // Filter out unwanted files
            // - emacs backups (ending with ~)
            // - emacs lock files (#...#)
            // - dotfiles (starting with .)
            if file_name.starts_with('.') || file_name.starts_with('#') || file_name.ends_with('~')
            {
                debug!("Filtering out file: {:?}", file_name);
                continue;
            }

            // Only include regular files
            let metadata = entry
                .metadata()
                .await
                .map_err(|e| KqueueError::IoError(e))?;
            if metadata.is_file() {
                files.push(entry_path);
                debug!("Found file in directory: {:?}", entry_path);
            }
        }

        Ok(files)
    }
}

impl Drop for KqueueWatcher {
    fn drop(&mut self) {
        let kq = *self.kqueue_fd.get_ref();
        unsafe {
            libc::close(kq);
        }
        debug!("Closed kqueue fd {}", kq);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_kqueue_watcher_creation() {
        let watcher = KqueueWatcher::new().await;
        assert!(watcher.is_ok());
    }

    #[tokio::test]
    async fn test_watch_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        File::create(&file_path).unwrap();

        let mut watcher = KqueueWatcher::new().await.unwrap();
        let result = watcher.watch_file(file_path.clone()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_watch_nonexistent_file() {
        let mut watcher = KqueueWatcher::new().await.unwrap();
        let result = watcher.watch_file("/nonexistent/file".into()).await;
        assert!(matches!(result, Err(KqueueError::FileNotFound(_))));
    }

    #[tokio::test]
    async fn test_watch_directory() {
        let temp_dir = TempDir::new().unwrap();
        let mut watcher = KqueueWatcher::new().await.unwrap();
        let result = watcher.watch_directory(temp_dir.path().to_path_buf()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unwatch_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        File::create(&file_path).unwrap();

        let mut watcher = KqueueWatcher::new().await.unwrap();
        watcher.watch_file(file_path.clone()).await.unwrap();
        let result = watcher.unwatch(&file_path).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_file_modification_event() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();

        let mut watcher = KqueueWatcher::new().await.unwrap();
        watcher.watch_file(file_path.clone()).await.unwrap();

        // Modify the file
        writeln!(file, "test data").unwrap();
        file.sync_all().unwrap();
        drop(file);

        // Wait for event with timeout
        let event =
            tokio::time::timeout(std::time::Duration::from_secs(2), watcher.next_event()).await;

        assert!(event.is_ok());
        if let Ok(Some(FileEvent::FileModified(path))) = event {
            assert_eq!(path, file_path);
        }
    }

    #[tokio::test]
    async fn test_symlink_resolution() {
        let temp_dir = TempDir::new().unwrap();
        let target_path = temp_dir.path().join("target.txt");
        let link_path = temp_dir.path().join("link.txt");
        File::create(&target_path).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target_path, &link_path).unwrap();

        let watcher = KqueueWatcher::new().await.unwrap();
        let (resolved, is_symlink) = watcher.resolve_symlink(&link_path).await.unwrap();

        assert_eq!(resolved, target_path);
        assert!(is_symlink);
    }

    #[tokio::test]
    async fn test_directory_file_filtering() {
        let temp_dir = TempDir::new().unwrap();

        // Create various test files
        File::create(temp_dir.path().join("normal.txt")).unwrap();
        File::create(temp_dir.path().join(".hidden")).unwrap();
        File::create(temp_dir.path().join("backup~")).unwrap();
        File::create(temp_dir.path().join("#lock#")).unwrap();

        let watcher = KqueueWatcher::new().await.unwrap();
        let files = watcher.read_directory_files(temp_dir.path()).await.unwrap();

        // Should only contain normal.txt
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("normal.txt"));
    }
}
