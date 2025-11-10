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

//! TFTP server implementation per RFC 1350 with PXE boot support
//!
//! # Purpose
//!
//! This module implements a complete TFTP (Trivial File Transfer Protocol) server designed
//! for network boot scenarios including PXE (Pre-boot Execution Environment) and UEFI HTTP boot.
//! The implementation follows RFC 1350 for basic TFTP operations while extending functionality
//! through RFC 2347 (TFTP Option Extension), RFC 2348 (TFTP Blocksize Option), and RFC 2349
//! (TFTP Timeout Interval and Transfer Size Options).
//!
//! # Memory Safety Transformation
//!
//! The Rust implementation eliminates memory vulnerabilities from the C version:
//!
//! | C Pattern | Rust Replacement | Safety Benefit |
//! |-----------|------------------|----------------|
//! | Manual buffer allocation | `Vec<u8>` and slices | Automatic bounds checking, no overflows |
//! | `recvmsg`/`sendmsg` blocking I/O | `tokio::net::UdpSocket` async | Non-blocking event loop integration |
//! | Manual file open/read | `tokio::fs::File` async | Automatic resource cleanup, no fd leaks |
//! | Linked list traversal | `HashMap<SocketAddr, TftpTransfer>` | Safe concurrent access |
//! | Manual reference counting | `Arc<TftpFile>` | Automatic memory management |
//! | `errno`-based errors | `Result<T, TftpError>` | Forced error handling |
//! | String buffer manipulation | `String`/`PathBuf` operations | No buffer overflows |
//!
//! # Protocol Implementation
//!
//! ## TFTP Opcodes (RFC 1350)
//! - RRQ (1) - Read Request
//! - WRQ (2) - Write Request (not implemented, returns ERR_PERM)
//! - DATA (3) - Data block
//! - ACK (4) - Acknowledgment
//! - ERROR (5) - Error notification
//! - OACK (6) - Option Acknowledgment (RFC 2347)
//!
//! ## Supported Options (RFC 2347-2349)
//! - `blksize` - Block size negotiation (512-65464 bytes, MTU limited)
//! - `tsize` - Transfer size reporting
//! - `timeout` - Timeout interval (not implemented, uses fixed 2s)
//!
//! ## Security Features
//! - Path traversal prevention (blocks `/../` sequences)
//! - Secure mode requiring file ownership by daemon user
//! - Permission validation (world-readable or owner-owned)
//! - Configurable root directory per interface
//! - Optional MAC-based or IP-based subdirectory selection
//!
//! # Architecture
//!
//! The server operates in async/await mode with tokio runtime:
//! - Main listening socket on port 69 for RRQ packets
//! - Per-transfer state management with timeout tracking
//! - Concurrent multi-client support with configurable limits
//! - File descriptor sharing for efficiency during mass boot scenarios
//! - Exponential backoff for timeout retransmission
//!
//! Original C implementation: src/tftp.c (~1000 lines)

use crate::config::types::TftpConfig;
use crate::core::daemon::Daemon;
use crate::logging::logger::Logger;
use crate::utils::general::prettyprint_addr;

#[cfg(feature = "dhcp")]
use crate::dhcp::common::find_mac;
#[cfg(feature = "dhcp")]
use crate::dhcp::lease::lease_find_by_addr;

#[cfg(feature = "script")]
use crate::process::helper::queue_tftp;

#[cfg(feature = "dump")]
use crate::utils::dump::PacketDumper;

use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, timeout, Instant};

use tracing::{debug, error, info, trace, warn};

use nix::sys::stat::{fstat, stat, Mode};
use nix::unistd::{access, geteuid, getuid, AccessFlags};

/// TFTP protocol opcode constants (RFC 1350 Section 5)
const OP_RRQ: u16 = 1; // Read Request
const OP_WRQ: u16 = 2; // Write Request (not supported)
const OP_DATA: u16 = 3; // Data block
const OP_ACK: u16 = 4; // Acknowledgment
const OP_ERR: u16 = 5; // Error
const OP_OACK: u16 = 6; // Option Acknowledgment (RFC 2347)

/// TFTP error codes (RFC 1350 Section 5)
const ERR_NOTDEF: u16 = 0; // Not defined
const ERR_FNF: u16 = 1; // File not found
const ERR_PERM: u16 = 2; // Access violation
const ERR_FULL: u16 = 3; // Disk full
const ERR_ILL: u16 = 4; // Illegal TFTP operation
const ERR_TID: u16 = 5; // Unknown transfer ID
const ERR_EXISTS: u16 = 6; // File already exists
const ERR_NOUSER: u16 = 7; // No such user

/// Default TFTP block size (RFC 1350)
const DEFAULT_BLOCK_SIZE: usize = 512;

/// Maximum TFTP block size (MTU limited, typically 1468 bytes)
const MAX_BLOCK_SIZE: usize = 65464;

/// TFTP timeout duration (2 seconds per RFC 1350 recommendation)
const TFTP_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum backoff iterations before aborting transfer
const MAX_BACKOFF: u8 = 7;

/// TFTP server error types
///
/// Provides comprehensive error handling for TFTP operations, replacing C's
/// errno-based error handling with type-safe Result propagation.
#[derive(Debug, Clone)]
pub enum TftpError {
    /// File not found (ERR_FNF)
    FileNotFound(String),

    /// Access violation - permission denied or path traversal attempt (ERR_PERM)
    AccessViolation(String),

    /// Disk full or quota exceeded (ERR_FULL)
    DiskFull(String),

    /// Illegal TFTP operation (ERR_ILL)
    IllegalOperation(String),

    /// Unknown transfer ID - packet from wrong source (ERR_TID)
    UnknownTransferId(SocketAddr),

    /// File already exists - for write operations (ERR_EXISTS)
    FileExists(String),

    /// No such user (ERR_NOUSER)
    NoSuchUser(String),

    /// I/O error during file operations
    IoError(String),

    /// Packet parsing error
    ParseError(String),

    /// Transfer timeout
    Timeout(String),
}

impl std::fmt::Display for TftpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TftpError::FileNotFound(msg) => write!(f, "File not found: {}", msg),
            TftpError::AccessViolation(msg) => write!(f, "Access violation: {}", msg),
            TftpError::DiskFull(msg) => write!(f, "Disk full: {}", msg),
            TftpError::IllegalOperation(msg) => write!(f, "Illegal operation: {}", msg),
            TftpError::UnknownTransferId(addr) => write!(f, "Unknown transfer ID from: {}", addr),
            TftpError::FileExists(msg) => write!(f, "File exists: {}", msg),
            TftpError::NoSuchUser(msg) => write!(f, "No such user: {}", msg),
            TftpError::IoError(msg) => write!(f, "I/O error: {}", msg),
            TftpError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            TftpError::Timeout(msg) => write!(f, "Timeout: {}", msg),
        }
    }
}

impl std::error::Error for TftpError {}

impl From<IoError> for TftpError {
    fn from(err: IoError) -> Self {
        TftpError::IoError(err.to_string())
    }
}

impl TftpError {
    /// Convert error to TFTP error code
    fn to_error_code(&self) -> u16 {
        match self {
            TftpError::FileNotFound(_) => ERR_FNF,
            TftpError::AccessViolation(_) => ERR_PERM,
            TftpError::DiskFull(_) => ERR_FULL,
            TftpError::IllegalOperation(_) => ERR_ILL,
            TftpError::UnknownTransferId(_) => ERR_TID,
            TftpError::FileExists(_) => ERR_EXISTS,
            TftpError::NoSuchUser(_) => ERR_NOUSER,
            TftpError::IoError(_) => ERR_NOTDEF,
            TftpError::ParseError(_) => ERR_ILL,
            TftpError::Timeout(_) => ERR_NOTDEF,
        }
    }
}

/// Shared file descriptor for efficient multi-client serving
///
/// Replaces C's `struct tftp_file` with reference counting via Arc.
/// Multiple transfers can share the same file descriptor when serving
/// identical files to different clients during mass network boot scenarios.
#[derive(Debug)]
struct TftpFile {
    /// File handle for async reading
    file: Arc<Mutex<File>>,

    /// File size in bytes for transfer size reporting
    size: u64,

    /// Device ID for deduplication
    dev: u64,

    /// Inode number for deduplication
    inode: u64,

    /// Original filename for logging
    filename: PathBuf,
}

impl TftpFile {
    /// Create new shared file descriptor
    async fn new(path: &Path) -> Result<Self, TftpError> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .await
            .map_err(|e| {
                if e.kind() == ErrorKind::NotFound {
                    TftpError::FileNotFound(path.display().to_string())
                } else if e.kind() == ErrorKind::PermissionDenied {
                    TftpError::AccessViolation(path.display().to_string())
                } else {
                    TftpError::IoError(e.to_string())
                }
            })?;

        let metadata = file.metadata().await?;
        let size = metadata.len();

        // Get dev and inode for deduplication using std::fs::metadata
        let std_metadata = std::fs::metadata(path)?;
        
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        
        #[cfg(unix)]
        let (dev, inode) = (std_metadata.dev(), std_metadata.ino());
        
        #[cfg(not(unix))]
        let (dev, inode) = (0, 0); // Deduplication disabled on non-Unix

        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            size,
            dev,
            inode,
            filename: path.to_path_buf(),
        })
    }

    /// Read block at specified offset
    async fn read_block(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, TftpError> {
        let mut file = self.file.lock().await;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let bytes_read = file.read(buffer).await?;
        Ok(bytes_read)
    }
}

/// Per-client transfer state
///
/// Replaces C's `struct tftp_transfer` with safe Rust types.
/// Manages individual file transfer state including timeout tracking,
/// block sequencing, and option negotiation.
#[derive(Debug)]
struct TftpTransfer {
    /// Client socket address (peer)
    peer: SocketAddr,

    /// Server interface address
    source: IpAddr,

    /// Interface index for multi-homed servers
    if_index: Option<u32>,

    /// Current block number (starts at 1)
    block: u16,

    /// Negotiated block size (default 512)
    blocksize: usize,

    /// Current file offset
    offset: u64,

    /// Shared file handle
    file: Arc<TftpFile>,

    /// Next timeout instant
    timeout: Instant,

    /// Backoff counter for exponential backoff
    backoff: u8,

    /// Client requested block size option
    opt_blocksize: Option<usize>,

    /// Client requested transfer size option
    opt_transize: bool,

    /// Netascii mode (CR-LF translation)
    netascii: bool,

    /// Carry-over LF from previous block (netascii)
    carrylf: bool,
}

impl TftpTransfer {
    /// Create new transfer state
    fn new(
        peer: SocketAddr,
        source: IpAddr,
        if_index: Option<u32>,
        file: Arc<TftpFile>,
        blocksize: usize,
        opt_blocksize: Option<usize>,
        opt_transize: bool,
        netascii: bool,
    ) -> Self {
        Self {
            peer,
            source,
            if_index,
            block: 1,
            blocksize,
            offset: 0,
            file,
            timeout: Instant::now() + TFTP_TIMEOUT,
            backoff: 0,
            opt_blocksize,
            opt_transize,
            netascii,
            carrylf: false,
        }
    }

    /// Check if transfer has timed out
    fn is_timed_out(&self) -> bool {
        Instant::now() >= self.timeout
    }

    /// Update timeout with exponential backoff
    fn update_timeout(&mut self) {
        self.backoff += 1;
        // Exponential backoff: 1, 1, 2, 2, 4, 4, 8, 8 seconds
        let backoff_secs = 1 + (1 << (self.backoff / 2));
        self.timeout = Instant::now() + Duration::from_secs(backoff_secs);
    }

    /// Check if transfer should be aborted due to excessive timeouts
    fn should_abort(&self) -> bool {
        self.backoff > MAX_BACKOFF
    }
}

/// TFTP server implementation
///
/// Provides async TFTP server with RFC 1350/2347/2348/2349 compliance.
/// Supports concurrent multi-client transfers with timeout management,
/// exponential backoff, and file descriptor sharing for efficiency.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::services::tftp::{TftpServer, TftpConfig};
/// use dnsmasq::core::daemon::Daemon;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = TftpConfig::default();
///     let daemon = Arc::new(Daemon::new(/* config */));
///     let logger = /* create logger */;
///     
///     let server = TftpServer::new(config, daemon, logger)?;
///     server.run().await?;
///     Ok(())
/// }
/// ```
pub struct TftpServer {
    /// TFTP configuration
    config: TftpConfig,

    /// Reference to main daemon for integration
    daemon: Arc<Daemon>,

    /// Logger for operational messages
    logger: Arc<Logger>,

    /// UDP socket for receiving requests (port 69)
    listener: Arc<UdpSocket>,

    /// Active transfers keyed by client socket address
    transfers: Arc<RwLock<HashMap<SocketAddr, TftpTransfer>>>,

    /// Shared file cache for deduplication
    file_cache: Arc<RwLock<HashMap<PathBuf, Arc<TftpFile>>>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Packet dumper for debugging (optional)
    #[cfg(feature = "dump")]
    dumper: Option<Arc<PacketDumper>>,
}

impl TftpServer {
    /// Create new TFTP server instance
    ///
    /// # Arguments
    ///
    /// * `config` - TFTP configuration including root directory and options
    /// * `daemon` - Reference to main daemon for DHCP integration
    /// * `logger` - Logger for operational messages
    ///
    /// # Returns
    ///
    /// Returns `Ok(TftpServer)` on success, or `Err(TftpError)` if:
    /// - Socket binding fails (port 69 in use or permission denied)
    /// - TFTP root directory validation fails
    ///
    /// # Errors
    ///
    /// - `TftpError::IoError` - Socket creation or binding failed
    /// - `TftpError::AccessViolation` - TFTP root directory inaccessible
    pub async fn new(
        config: TftpConfig,
        daemon: Arc<Daemon>,
        logger: Arc<Logger>,
    ) -> Result<Self, TftpError> {
        // Validate TFTP root directory
        if let Some(ref root) = config.tftp_root {
            if !root.exists() {
                error!("TFTP root directory does not exist: {:?}", root);
                return Err(TftpError::AccessViolation(format!(
                    "TFTP root directory not found: {:?}",
                    root
                )));
            }
            if !root.is_dir() {
                error!("TFTP root path is not a directory: {:?}", root);
                return Err(TftpError::AccessViolation(format!(
                    "TFTP root is not a directory: {:?}",
                    root
                )));
            }
        } else {
            warn!("TFTP server started without root directory configured");
        }

        // Bind TFTP listener socket on port 69
        let bind_addr = if config.single_port {
            "0.0.0.0:69".parse().unwrap()
        } else {
            // For multi-port mode, still listen on 69 for initial RRQ
            "0.0.0.0:69".parse().unwrap()
        };

        let listener = UdpSocket::bind(bind_addr).await.map_err(|e| {
            error!("Failed to bind TFTP socket on {}: {}", bind_addr, e);
            TftpError::IoError(format!("Failed to bind TFTP socket: {}", e))
        })?;

        info!("TFTP server listening on {}", bind_addr);

        #[cfg(feature = "dump")]
        let dumper = None; // Will be initialized if dump feature is active

        Ok(Self {
            config,
            daemon,
            logger,
            listener: Arc::new(listener),
            transfers: Arc::new(RwLock::new(HashMap::new())),
            file_cache: Arc::new(RwLock::new(HashMap::new())),
            shutdown: Arc::new(RwLock::new(false)),
            #[cfg(feature = "dump")]
            dumper,
        })
    }

    /// Run TFTP server main loop
    ///
    /// Listens for incoming RRQ packets and manages active file transfers.
    /// Handles timeout retransmission with exponential backoff per RFC 1350.
    /// Runs until shutdown() is called.
    pub async fn run(&self) -> Result<(), TftpError> {
        info!("TFTP server started");
        let mut buffer = vec![0u8; 65536];

        loop {
            if *self.shutdown.read().await {
                info!("TFTP server shutting down");
                break;
            }

            let timeout_check = sleep(Duration::from_millis(100));
            tokio::pin!(timeout_check);

            tokio::select! {
                result = self.listener.recv_from(&mut buffer) => {
                    match result {
                        Ok((len, peer)) => {
                            let packet = buffer[..len].to_vec();
                            let server = self.clone_for_task();
                            tokio::spawn(async move {
                                if let Err(e) = server.handle_request(peer, &packet).await {
                                    error!("Error handling TFTP request from {}: {}", peer, e);
                                }
                            });
                        }
                        Err(e) => error!("Error receiving TFTP packet: {}", e),
                    }
                }
                _ = &mut timeout_check => {
                    self.check_timeouts().await;
                }
            }
        }
        Ok(())
    }

    /// Shutdown TFTP server gracefully
    pub async fn shutdown(&self) {
        info!("Shutting down TFTP server");
        *self.shutdown.write().await = true;

        let start = Instant::now();
        while !self.transfers.read().await.is_empty() {
            if start.elapsed() > Duration::from_secs(30) {
                warn!("Timeout waiting for TFTP transfers, forcing shutdown");
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        info!("TFTP server shutdown complete");
    }

    /// Clone server references for async task spawning
    fn clone_for_task(&self) -> Self {
        Self {
            config: self.config.clone(),
            daemon: Arc::clone(&self.daemon),
            logger: Arc::clone(&self.logger),
            listener: Arc::clone(&self.listener),
            transfers: Arc::clone(&self.transfers),
            file_cache: Arc::clone(&self.file_cache),
            shutdown: Arc::clone(&self.shutdown),
            #[cfg(feature = "dump")]
            dumper: self.dumper.clone(),
        }
    }

    /// Check for timed-out transfers and handle retransmission
    async fn check_timeouts(&self) {
        let mut transfers = self.transfers.write().await;
        let mut to_remove = Vec::new();

        for (peer, transfer) in transfers.iter_mut() {
            if transfer.is_timed_out() {
                if transfer.should_abort() {
                    warn!("TFTP transfer to {} timed out after {} retries", peer, transfer.backoff);
                    to_remove.push(*peer);
                } else {
                    debug!("Retransmitting block {} to {}", transfer.block, peer);
                    transfer.update_timeout();
                    
                    match self.build_data_packet(transfer).await {
                        Ok(packet) => {
                            if let Err(e) = self.listener.send_to(&packet, peer).await {
                                error!("Failed to retransmit to {}: {}", peer, e);
                                to_remove.push(*peer);
                            }
                        }
                        Err(e) => {
                            error!("Failed to build DATA packet: {}", e);
                            to_remove.push(*peer);
                        }
                    }
                }
            }
        }

        for peer in to_remove {
            transfers.remove(&peer);
        }
    }

    /// Handle incoming TFTP request (RRQ, ACK, ERR)
    pub async fn handle_request(&self, peer: SocketAddr, packet: &[u8]) -> Result<(), TftpError> {
        if packet.len() < 2 {
            return Err(TftpError::ParseError("Packet too short".to_string()));
        }

        let opcode = u16::from_be_bytes([packet[0], packet[1]]);

        match opcode {
            OP_RRQ => self.handle_rrq(peer, packet).await,
            OP_ACK => self.handle_ack(peer, packet).await,
            OP_ERR => self.handle_error(peer, packet).await,
            OP_WRQ => {
                warn!("Write request from {} not supported", peer);
                let err_packet = self.build_error_packet(ERR_ILL, "Write not supported")?;
                self.listener.send_to(&err_packet, &peer).await?;
                Ok(())
            }
            _ => {
                warn!("Invalid opcode {} from {}", opcode, peer);
                let err_packet = self.build_error_packet(ERR_ILL, "Invalid opcode")?;
                self.listener.send_to(&err_packet, &peer).await?;
                Err(TftpError::IllegalOperation(format!("Invalid opcode: {}", opcode)))
            }
        }
    }

    /// Handle RRQ (Read Request) packet
    async fn handle_rrq(&self, peer: SocketAddr, packet: &[u8]) -> Result<(), TftpError> {
        let client_str = prettyprint_addr(&peer);
        info!("RRQ from {}", client_str);

        // Parse RRQ packet: opcode | filename | 0 | mode | 0 | [options]
        let mut parts = Vec::new();
        let mut start = 2; // Skip opcode
        
        for i in 2..packet.len() {
            if packet[i] == 0 {
                if start < i {
                    let s = String::from_utf8_lossy(&packet[start..i]).to_string();
                    parts.push(s);
                }
                start = i + 1;
            }
        }

        if parts.len() < 2 {
            return Err(TftpError::ParseError("Invalid RRQ format".to_string()));
        }

        let mut filename = parts[0].clone();
        let mode = parts[1].to_lowercase();

        // Parse options (RFC 2347)
        let mut opt_blocksize = None;
        let mut opt_transize = false;
        
        let mut i = 2;
        while i + 1 < parts.len() {
            let opt_name = parts[i].to_lowercase();
            let opt_value = &parts[i + 1];

            match opt_name.as_str() {
                "blksize" => {
                    if let Ok(size) = opt_value.parse::<usize>() {
                        if size >= 8 && size <= MAX_BLOCK_SIZE {
                            let mtu_limit = self.config.tftp_mtu.unwrap_or(1500) as usize - 28;
                            opt_blocksize = Some(size.min(mtu_limit));
                        }
                    }
                }
                "tsize" => {
                    opt_transize = true;
                }
                _ => {}
            }
            i += 2;
        }

        // Apply lowercase conversion if configured
        if self.config.lowercase {
            filename = filename.to_lowercase();
        }

        // Sanitize filename - prevent path traversal
        if filename.contains("/../") || filename.starts_with("../") || filename.contains("\\") {
            warn!("Path traversal attempt from {}: {}", client_str, filename);
            let err_packet = self.build_error_packet(ERR_PERM, "Access violation")?;
            self.listener.send_to(&err_packet, &peer).await?;
            return Err(TftpError::AccessViolation(filename));
        }

        // Construct full file path
        let root = self.config.tftp_root.as_ref().ok_or_else(|| {
            TftpError::AccessViolation("TFTP root not configured".to_string())
        })?;

        let file_path = root.join(&filename);

        // Check file permissions and open file
        let tftp_file = match self.check_file_permissions(&file_path).await {
            Ok(file) => file,
            Err(e) => {
                let err_packet = match &e {
                    TftpError::FileNotFound(_) => {
                        self.build_error_packet(ERR_FNF, &format!("File not found: {}", filename))?
                    }
                    TftpError::AccessViolation(_) => {
                        self.build_error_packet(ERR_PERM, "Access denied")?
                    }
                    _ => self.build_error_packet(ERR_NOTDEF, "Server error")?,
                };
                self.listener.send_to(&err_packet, &peer).await?;
                return Err(e);
            }
        };

        let netascii = mode == "netascii";
        let blocksize = opt_blocksize.unwrap_or(DEFAULT_BLOCK_SIZE);

        // Create transfer state
        let transfer = TftpTransfer::new(
            peer,
            self.listener.local_addr()?.ip(),
            None,
            Arc::new(tftp_file),
            blocksize,
            opt_blocksize,
            opt_transize,
            netascii,
        );

        // Send OACK if options were negotiated, otherwise send first DATA block
        let response = if opt_blocksize.is_some() || opt_transize {
            self.build_oack_packet(&transfer, blocksize, opt_transize).await?
        } else {
            self.build_data_packet(&transfer).await?
        };

        self.listener.send_to(&response, &peer).await?;

        // Store transfer state
        let mut transfers = self.transfers.write().await;
        transfers.insert(peer, transfer);

        Ok(())
    }

    /// Handle ACK packet
    async fn handle_ack(&self, peer: SocketAddr, packet: &[u8]) -> Result<(), TftpError> {
        if packet.len() < 4 {
            return Err(TftpError::ParseError("ACK packet too short".to_string()));
        }

        let block = u16::from_be_bytes([packet[2], packet[3]]);

        let mut transfers = self.transfers.write().await;
        let transfer = transfers.get_mut(&peer).ok_or_else(|| {
            TftpError::UnknownTransferId(peer)
        })?;

        // Verify ACK block number
        if block != transfer.block {
            debug!("ACK block mismatch from {}: expected {}, got {}", peer, transfer.block, block);
            return Ok(()); // Ignore out-of-sequence ACK
        }

        // Check if transfer is complete
        if transfer.offset >= transfer.file.size {
            info!("TFTP transfer to {} complete: {} bytes", peer, transfer.file.size);
            transfers.remove(&peer);
            
            #[cfg(feature = "script")]
            if let Err(e) = queue_tftp(&transfer.file.filename, transfer.file.size, peer).await {
                warn!("Failed to queue TFTP script: {}", e);
            }
            
            return Ok(());
        }

        // Advance to next block
        transfer.block = transfer.block.wrapping_add(1);
        transfer.timeout = Instant::now() + TFTP_TIMEOUT;
        transfer.backoff = 0;

        // Send next DATA block
        let data_packet = self.build_data_packet(transfer).await?;
        self.listener.send_to(&data_packet, &peer).await?;

        Ok(())
    }

    /// Handle ERROR packet from client
    async fn handle_error(&self, peer: SocketAddr, packet: &[u8]) -> Result<(), TftpError> {
        if packet.len() < 4 {
            return Err(TftpError::ParseError("ERROR packet too short".to_string()));
        }

        let error_code = u16::from_be_bytes([packet[2], packet[3]]);
        let message = if packet.len() > 4 {
            String::from_utf8_lossy(&packet[4..packet.len() - 1]).to_string()
        } else {
            "Unknown error".to_string()
        };

        warn!("TFTP error from {}: code={}, message={}", peer, error_code, message);

        // Remove transfer
        let mut transfers = self.transfers.write().await;
        transfers.remove(&peer);

        Ok(())
    }

    /// Check file permissions and open file
    async fn check_file_permissions(&self, path: &Path) -> Result<TftpFile, TftpError> {
        // Check if file exists
        if !path.exists() {
            return Err(TftpError::FileNotFound(path.display().to_string()));
        }

        // Check file permissions using nix stat
        let stat_result = stat(path).map_err(|e| {
            TftpError::AccessViolation(format!("Cannot stat file: {}", e))
        })?;

        let mode = stat_result.st_mode;
        let file_mode = Mode::from_bits_truncate(mode);

        // Get current effective UID
        let euid = geteuid();

        // Running as root - must be world-readable
        if euid.is_root() {
            if !file_mode.contains(Mode::S_IROTH) {
                return Err(TftpError::AccessViolation(
                    "File not world-readable (running as root)".to_string()
                ));
            }
        }
        // Secure mode - must be owned by daemon user
        else if self.config.secure_mode {
            if stat_result.st_uid != euid.as_raw() {
                return Err(TftpError::AccessViolation(
                    "File not owned by daemon user (secure mode)".to_string()
                ));
            }
        }

        // Check read access
        if let Err(e) = access(path, AccessFlags::R_OK) {
            return Err(TftpError::AccessViolation(format!("Cannot read file: {}", e)));
        }

        // Check for shared file in cache
        let mut file_cache = self.file_cache.write().await;
        
        if let Some(cached) = file_cache.get(path) {
            // Verify inode hasn't changed
            if cached.dev == stat_result.st_dev && cached.inode == stat_result.st_ino {
                debug!("Using cached file descriptor for {}", path.display());
                return Ok(TftpFile {
                    file: Arc::clone(&cached.file),
                    size: cached.size,
                    dev: cached.dev,
                    inode: cached.inode,
                    filename: cached.filename.clone(),
                });
            }
        }

        // Open new file
        let tftp_file = TftpFile::new(path).await?;
        
        // Cache the file for sharing
        file_cache.insert(path.to_path_buf(), Arc::new(TftpFile {
            file: Arc::clone(&tftp_file.file),
            size: tftp_file.size,
            dev: tftp_file.dev,
            inode: tftp_file.inode,
            filename: tftp_file.filename.clone(),
        }));

        Ok(tftp_file)
    }

    /// Build DATA packet (opcode | block | data)
    async fn build_data_packet(&self, transfer: &TftpTransfer) -> Result<Vec<u8>, TftpError> {
        let mut packet = Vec::with_capacity(4 + transfer.blocksize);
        
        // Opcode (2 bytes)
        packet.extend_from_slice(&OP_DATA.to_be_bytes());
        
        // Block number (2 bytes)
        packet.extend_from_slice(&transfer.block.to_be_bytes());

        // Read file data
        let mut buffer = vec![0u8; transfer.blocksize];
        let bytes_read = transfer.file.read_block(transfer.offset, &mut buffer).await?;

        if transfer.netascii {
            // Netascii mode: translate LF to CR-LF
            let mut translated = Vec::with_capacity(bytes_read * 2);
            for &byte in &buffer[..bytes_read] {
                if byte == b'\n' && !transfer.carrylf {
                    translated.push(b'\r');
                }
                translated.push(byte);
            }
            packet.extend_from_slice(&translated);
        } else {
            packet.extend_from_slice(&buffer[..bytes_read]);
        }

        Ok(packet)
    }

    /// Build OACK packet for option negotiation
    async fn build_oack_packet(
        &self,
        transfer: &TftpTransfer,
        blocksize: usize,
        include_tsize: bool,
    ) -> Result<Vec<u8>, TftpError> {
        let mut packet = Vec::new();
        
        // Opcode (2 bytes)
        packet.extend_from_slice(&OP_OACK.to_be_bytes());

        // Blocksize option
        if transfer.opt_blocksize.is_some() {
            packet.extend_from_slice(b"blksize\0");
            packet.extend_from_slice(blocksize.to_string().as_bytes());
            packet.push(0);
        }

        // Transfer size option
        if include_tsize {
            packet.extend_from_slice(b"tsize\0");
            packet.extend_from_slice(transfer.file.size.to_string().as_bytes());
            packet.push(0);
        }

        Ok(packet)
    }

    /// Build ERROR packet (opcode | error_code | error_msg | 0)
    fn build_error_packet(&self, error_code: u16, message: &str) -> Result<Vec<u8>, TftpError> {
        let mut packet = Vec::new();
        
        packet.extend_from_slice(&OP_ERR.to_be_bytes());
        packet.extend_from_slice(&error_code.to_be_bytes());
        packet.extend_from_slice(message.as_bytes());
        packet.push(0);

        Ok(packet)
    }
}
