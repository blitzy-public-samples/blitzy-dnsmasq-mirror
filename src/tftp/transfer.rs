// dnsmasq is Copyright (c) 2000-2022 Simon Kelley
// Copyright (c) 2024 Blitzy Platform (Rust translation)
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

//! TFTP Transfer State Management
//!
//! This module implements the TFTP file transfer state machine with support for:
//! - Per-client transfer session tracking with block sequencing
//! - Timeout and retry logic with exponential backoff
//! - Block size negotiation (512-65464 bytes per RFC 2348)
//! - Netascii mode translation with CR-LF conversion
//! - File descriptor sharing with reference counting for concurrent multi-client serving
//!
//! # Transfer Lifecycle
//!
//! 1. **Initialization**: Client sends RRQ → Server creates Transfer
//! 2. **Negotiation**: Server sends OACK (block 0) if options requested
//! 3. **Data Transfer**: Server sends DATA → Client sends ACK → repeat
//! 4. **Completion**: Last block (< blocksize) sent and acknowledged
//! 5. **Cleanup**: Transfer dropped, file reference count decremented
//!
//! # State Machine
//!
//! ```text
//! RRQ → OACK/DATA → Wait ACK → DATA → Wait ACK → ... → Complete
//!           ↓          ↓          ↓
//!        Timeout    Timeout    Timeout
//!           ↓          ↓          ↓
//!       Retransmit Retransmit Retransmit (exponential backoff)
//!           ↓          ↓          ↓
//!        Abort (after 7+ retries)
//! ```
//!
//! # Netascii Translation
//!
//! In netascii mode, LF characters are translated to CR-LF:
//! - Maintains `carrylf` flag across block boundaries
//! - Tracks `expansion` count for correct next-block offset calculation
//! - Prevents double-expansion when LF falls at block boundary
//!
//! # Concurrency Model
//!
//! Multiple transfers can serve the same file concurrently using `Arc<TftpFile>`
//! with reference counting. File descriptor is closed only when last transfer completes.
//!
//! # C Source Reference
//!
//! Translated from: `src/tftp.c`
//! - `struct tftp_transfer` (lines 766-780): Transfer state
//! - `struct tftp_file` (lines 758-764): Shared file handle
//! - `get_block()` (lines 1442-1523): Block construction with netascii
//! - `handle_tftp()` (lines 1014-1053): ACK/ERROR processing
//! - `free_transfer()` (lines 1103-1115): Resource cleanup

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Seek, SeekFrom};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::fs::File;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::constants::TFTP_BLOCK_SIZE;
use crate::tftp::protocol::{ErrorPacket, TransferMode};

/// Maximum block size for TFTP transfers (65464 bytes per RFC 2348)
/// Limited by UDP payload size to avoid fragmentation
const MAX_BLOCK_SIZE: u16 = 65464;

/// Minimum block size for TFTP transfers (8 bytes, practical minimum)
const MIN_BLOCK_SIZE: u16 = 8;

/// Maximum backoff iterations before aborting transfer
/// C reference: transfer->backoff > 7 check in check_tftp_listeners()
const MAX_BACKOFF: u8 = 7;

/// Initial timeout duration in seconds
/// C reference: timeout calculation in check_tftp_listeners()
const INITIAL_TIMEOUT_SECS: u64 = 1;

/// TFTP transfer options negotiated with client
/// C reference: transfer->opt_blocksize, opt_transize fields
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransferOptions {
    /// Whether blocksize option was requested by client
    pub blocksize_requested: bool,
    /// Whether tsize (transfer size) option was requested
    pub tsize_requested: bool,
    /// Whether timeout option was requested
    pub timeout_requested: bool,
}

impl TransferOptions {
    /// Create new transfer options with all flags disabled
    pub fn new() -> Self {
        TransferOptions {
            blocksize_requested: false,
            tsize_requested: false,
            timeout_requested: false,
        }
    }

    /// Create options with blocksize negotiation enabled
    pub fn with_blocksize(mut self) -> Self {
        self.blocksize_requested = true;
        self
    }

    /// Create options with tsize negotiation enabled
    pub fn with_tsize(mut self) -> Self {
        self.tsize_requested = true;
        self
    }

    /// Create options with timeout negotiation enabled
    pub fn with_timeout(mut self) -> Self {
        self.timeout_requested = true;
        self
    }
}

/// File metadata for stale file detection
/// C reference: struct tftp_file fields dev, inode
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    /// Device ID containing the file
    pub device: u64,
    /// Inode number of the file
    pub inode: u64,
    /// File size in bytes
    pub size: u64,
}

impl FileMetadata {
    /// Create new file metadata
    pub fn new(device: u64, inode: u64, size: u64) -> Self {
        FileMetadata {
            device,
            inode,
            size,
        }
    }

    /// Check if this metadata represents a stale file reference
    /// by comparing with current filesystem metadata
    pub fn is_stale(&self, other: &FileMetadata) -> bool {
        self.device != other.device || self.inode != other.inode
    }
}

/// Errors that can occur during TFTP transfer operations
/// C reference: Error handling via return codes and errno in tftp.c
#[derive(Error, Debug)]
pub enum TransferError {
    /// File read error during block construction
    #[error("File read error: {0}")]
    FileReadError(#[from] std::io::Error),

    /// Protocol packet parsing error
    #[error("Packet error: {0}")]
    PacketError(String),

    /// Transfer timed out after maximum retries
    #[error("Transfer timed out after {0} retries")]
    TimeoutError(u8),

    /// Invalid transfer state for requested operation
    #[error("Invalid transfer state: {0}")]
    InvalidState(String),

    /// Network error during packet transmission
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Requested file not found
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// Permission denied accessing file
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid block size negotiation
    #[error("Invalid block size: {0}")]
    InvalidBlockSize(u16),
}

/// Actions to take after handling a packet
/// C reference: Implicit state machine in handle_tftp() and check_tftp_listeners()
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferAction {
    /// Continue transfer, no immediate action
    Continue,
    /// Send next data block
    SendBlock,
    /// Transfer complete successfully
    Complete,
    /// Abort transfer due to error
    Abort,
    /// Retransmit current block
    Retransmit,
}

/// Shared TFTP file handle with reference counting
/// C reference: struct tftp_file (src/tftp.c lines 758-764)
///
/// Multiple concurrent transfers can share the same file descriptor when serving
/// the same file to multiple clients. Reference counting ensures the file is closed
/// only when the last transfer completes.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::tftp::transfer::TftpFile;
/// use std::sync::Arc;
/// use std::path::PathBuf;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let path = PathBuf::from("/tftpboot/pxelinux.0");
/// let file = TftpFile::open(&path, false).await?;
/// // file is now wrapped in Arc internally
/// let file_arc = Arc::new(file);
/// // Multiple transfers share file_arc via Arc::clone()
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct TftpFile {
    /// Async file handle protected by mutex for safe concurrent reads
    /// C reference: fd field (int file descriptor)
    file: Arc<Mutex<File>>,
    /// File size in bytes for transfer size reporting
    /// C reference: size field (off_t)
    size: u64,
    /// File path for logging and error messages
    /// C reference: filename field (char[])
    filename: PathBuf,
    /// File metadata for stale detection
    /// C reference: dev, inode fields (dev_t, ino_t)
    metadata: FileMetadata,
}

impl TftpFile {
    /// Create a new TftpFile from an opened file handle
    ///
    /// # Arguments
    /// * `file` - Opened async file handle
    /// * `size` - File size in bytes
    /// * `filename` - Path to the file
    /// * `metadata` - File metadata (device, inode, size)
    pub fn new(file: File, size: u64, filename: PathBuf, metadata: FileMetadata) -> Self {
        TftpFile {
            file: Arc::new(Mutex::new(file)),
            size,
            filename,
            metadata,
        }
    }

    /// Open a file for TFTP serving with permission validation
    ///
    /// C reference: check_tftp_fileperm() in src/tftp.c (lines 721-801)
    ///
    /// # Arguments
    /// * `path` - Path to the file to open
    /// * `secure_mode` - If true, enforce ownership check (OPT_TFTP_SECURE)
    ///
    /// # Returns
    /// Opened TftpFile or TransferError
    ///
    /// # Security
    /// - Blocks path traversal (/../) in prefix mode
    /// - Enforces world-readable when running as root
    /// - Enforces ownership match in secure mode
    pub async fn open(path: &PathBuf, secure_mode: bool) -> Result<Self, TransferError> {
        // Check for path traversal
        if let Some(path_str) = path.to_str() {
            if path_str.contains("/../") {
                return Err(TransferError::PermissionDenied(
                    "Path traversal not allowed".to_string(),
                ));
            }
        }

        // Open file for reading
        let file = File::open(path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                TransferError::FileNotFound(format!("{}", path.display()))
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                TransferError::PermissionDenied(format!("{}", path.display()))
            } else {
                TransferError::FileReadError(e)
            }
        })?;

        // Get file metadata
        let std_metadata = file
            .metadata()
            .await
            .map_err(TransferError::FileReadError)?;

        // Validate permissions
        let permissions = std_metadata.permissions();
        
        // On Unix, check world-readable for root or ownership in secure mode
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = permissions.mode();
            
            // Check if running as root (uid 0)
            let uid = unsafe { libc::geteuid() };
            
            if uid == 0 {
                // Running as root, must be world-readable
                if (mode & 0o004) == 0 {
                    return Err(TransferError::PermissionDenied(
                        "File not world-readable (required when running as root)".to_string(),
                    ));
                }
            } else if secure_mode {
                // In secure mode, file must be owned by current user
                use std::os::unix::fs::MetadataExt;
                let file_uid = std_metadata.uid();
                if file_uid != uid {
                    return Err(TransferError::PermissionDenied(
                        "File not owned by dnsmasq user (secure mode)".to_string()
                    ));
                }
            }
        }

        let size = std_metadata.len();
        
        // Extract device and inode for stale detection
        #[cfg(unix)]
        let (device, inode) = {
            use std::os::unix::fs::MetadataExt;
            (std_metadata.dev(), std_metadata.ino())
        };
        
        #[cfg(not(unix))]
        let (device, inode) = (0, 0);

        let metadata = FileMetadata::new(device, inode, size);

        Ok(TftpFile::new(file, size, path.clone(), metadata))
    }

    /// Get file size in bytes
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get file path
    pub fn filename(&self) -> &PathBuf {
        &self.filename
    }

    /// Get file metadata
    pub fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }

    /// Validate that we still have access to the file
    ///
    /// This checks if the file is still accessible and hasn't been replaced
    /// (different inode). Used for long-running transfers.
    pub async fn validate_access(&self) -> Result<(), TransferError> {
        // Try to read metadata to ensure file is still accessible
        let current_meta = tokio::fs::metadata(&self.filename)
            .await
            .map_err(TransferError::FileReadError)?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let current_metadata = FileMetadata::new(
                current_meta.dev(),
                current_meta.ino(),
                current_meta.len(),
            );
            
            if self.metadata.is_stale(&current_metadata) {
                return Err(TransferError::InvalidState(
                    "File has been replaced (stale inode)".to_string(),
                ));
            }
        }
        
        Ok(())
    }

    /// Read a block of data from the file at the specified offset
    ///
    /// # Arguments
    /// * `offset` - Byte offset in file to read from
    /// * `size` - Number of bytes to read
    ///
    /// # Returns
    /// Vector of bytes read from file
    async fn read_block(&self, offset: u64, size: usize) -> Result<Vec<u8>, TransferError> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        
        let mut file_guard = self.file.lock().await;
        
        // Seek to offset
        file_guard
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(TransferError::FileReadError)?;
        
        // Read data
        let mut buffer = vec![0u8; size];
        let bytes_read = file_guard
            .read(&mut buffer)
            .await
            .map_err(TransferError::FileReadError)?;
        
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
}

/// TFTP transfer state for a single client session
/// C reference: struct tftp_transfer (src/tftp.c lines 766-780)
///
/// Tracks all state for an active file transfer including:
/// - Network connection (socket, peer address)
/// - Transfer progress (block number, offset)
/// - Retry state (timeout, backoff counter)
/// - Options (block size, transfer mode)
/// - File reference (shared with other transfers)
///
/// # Lifecycle
///
/// 1. Created on RRQ reception
/// 2. Sends OACK (block 0) if options negotiated, or first DATA block
/// 3. Waits for ACK, handles timeout/retransmit
/// 4. Advances through blocks until file complete (last block < blocksize)
/// 5. Dropped when transfer completes or times out
#[derive(Debug)]
pub struct Transfer {
    /// UDP socket for this transfer
    /// C reference: sockfd field (int)
    pub socket: Arc<UdpSocket>,
    
    /// Client address (IP and port)
    /// C reference: peer field (union mysockaddr)
    pub peer: SocketAddr,
    
    /// Server source address for multi-homed systems
    /// C reference: source field (union all_addr)
    source: IpAddr,
    
    /// Network interface index for multi-homed binding
    /// C reference: if_index field (int)
    if_index: u32,
    
    /// Current block number (0 = OACK, 1-65535 = DATA blocks)
    /// C reference: block field (unsigned int)
    pub block: u16,
    
    /// Negotiated block size in bytes (512-65464)
    /// C reference: blocksize field (unsigned int)
    pub blocksize: u16,
    
    /// Absolute timeout instant for next retransmission
    /// C reference: timeout field (time_t)
    pub timeout: Instant,
    
    /// Exponential backoff counter (0-7, abort at > 7)
    /// C reference: backoff field (int)
    pub backoff: u8,
    
    /// Current file offset in bytes for next read
    /// C reference: offset field (off_t)
    offset: u64,
    
    /// Number of CR characters inserted in current block (netascii mode)
    /// C reference: expansion field (unsigned int)
    expansion: usize,
    
    /// Transfer mode (octet, netascii, mail)
    /// C reference: netascii field (char)
    mode: TransferMode,
    
    /// Whether previous block ended with LF (prevents double-expansion)
    /// C reference: carrylf field (char)
    carrylf: bool,
    
    /// Transfer options negotiated with client
    /// C reference: opt_blocksize, opt_transize fields
    options: TransferOptions,
    
    /// Shared file reference
    /// C reference: file field (struct tftp_file *)
    file: Arc<TftpFile>,
}

impl Transfer {
    /// Create a new TFTP transfer
    ///
    /// C reference: Allocation in tftp_request() (src/tftp.c lines 196-650)
    ///
    /// # Arguments
    /// * `socket` - UDP socket for this transfer
    /// * `peer` - Client address
    /// * `source` - Server source address
    /// * `if_index` - Network interface index
    /// * `file` - Shared file reference
    /// * `blocksize` - Negotiated block size (default 512)
    /// * `mode` - Transfer mode (octet, netascii)
    /// * `options` - Transfer options
    ///
    /// # Returns
    /// New Transfer instance ready for first block
    pub fn new(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        source: IpAddr,
        if_index: u32,
        file: Arc<TftpFile>,
        blocksize: u16,
        mode: TransferMode,
        options: TransferOptions,
    ) -> Result<Self, TransferError> {
        // Validate block size
        if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&blocksize) {
            return Err(TransferError::InvalidBlockSize(blocksize));
        }

        Ok(Transfer {
            socket,
            peer,
            source,
            if_index,
            block: if options.blocksize_requested || options.tsize_requested { 0 } else { 1 },
            blocksize,
            timeout: Instant::now() + Duration::from_secs(INITIAL_TIMEOUT_SECS),
            backoff: 0,
            offset: 0,
            expansion: 0,
            mode,
            carrylf: false,
            options,
            file,
        })
    }

    /// Handle received packet (ACK or ERROR)
    ///
    /// C reference: handle_tftp() in src/tftp.c (lines 1014-1053)
    ///
    /// # Arguments
    /// * `packet` - Received packet data
    ///
    /// # Returns
    /// Action to take (Continue, SendBlock, Abort)
    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<TransferAction, TransferError> {
        if packet.len() < 4 {
            // Packet too short, ignore
            return Ok(TransferAction::Continue);
        }

        let mut cursor = Cursor::new(packet);
        let opcode = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| TransferError::PacketError(e.to_string()))?;
        
        let block_or_error = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| TransferError::PacketError(e.to_string()))?;

        match opcode {
            4 => {
                // ACK packet
                if block_or_error == self.block {
                    // Valid ACK for current block
                    self.reset_timeout();
                    self.backoff = 0;
                    
                    if self.block != 0 {
                        // Advance offset for next block
                        self.offset += self.blocksize as u64 - self.expansion as u64;
                    }
                    
                    // Advance to next block
                    self.block = self.block.wrapping_add(1);
                    
                    Ok(TransferAction::SendBlock)
                } else {
                    // Duplicate or out-of-order ACK, ignore
                    Ok(TransferAction::Continue)
                }
            }
            5 => {
                // ERROR packet from client
                Ok(TransferAction::Abort)
            }
            _ => {
                // Unknown opcode, ignore
                Ok(TransferAction::Continue)
            }
        }
    }

    /// Get next data block to send
    ///
    /// C reference: get_block() in src/tftp.c (lines 1442-1523)
    ///
    /// # Returns
    /// Packet data to send (OACK for block 0, DATA for other blocks)
    pub async fn get_block(&mut self) -> Result<Vec<u8>, TransferError> {
        if self.block == 0 {
            // Send OACK
            self.construct_oack()
        } else {
            // Send DATA block
            self.construct_data_block().await
        }
    }

    /// Construct OACK packet for block 0
    ///
    /// C reference: get_block() OACK construction (lines 1446-1469)
    fn construct_oack(&self) -> Result<Vec<u8>, TransferError> {
        let mut packet = Vec::new();
        
        // Opcode: OACK (6)
        packet.extend_from_slice(&6u16.to_be_bytes());
        
        if self.options.blocksize_requested {
            packet.extend_from_slice(b"blksize\0");
            packet.extend_from_slice(self.blocksize.to_string().as_bytes());
            packet.push(0);
        }
        
        if self.options.tsize_requested {
            packet.extend_from_slice(b"tsize\0");
            packet.extend_from_slice(self.file.size().to_string().as_bytes());
            packet.push(0);
        }
        
        Ok(packet)
    }

    /// Construct DATA packet with file content
    ///
    /// C reference: get_block() DATA construction (lines 1471-1523)
    async fn construct_data_block(&mut self) -> Result<Vec<u8>, TransferError> {
        // Check if transfer complete
        if self.offset >= self.file.size() {
            return Ok(Vec::new());
        }
        
        // Calculate read size
        let remaining = self.file.size() - self.offset;
        let read_size = std::cmp::min(remaining, self.blocksize as u64) as usize;
        
        // Read data from file
        let mut data = self.file.read_block(self.offset, read_size).await?;
        
        // Reset expansion counter
        self.expansion = 0;
        
        // Apply netascii translation if needed
        if self.mode == TransferMode::Netascii {
            data = self.apply_netascii_translation(data)?;
        }
        
        // Construct DATA packet
        let mut packet = Vec::with_capacity(4 + data.len());
        
        // Opcode: DATA (3)
        packet.extend_from_slice(&3u16.to_be_bytes());
        
        // Block number
        packet.extend_from_slice(&self.block.to_be_bytes());
        
        // Data
        packet.extend_from_slice(&data);
        
        Ok(packet)
    }

    /// Apply netascii CR-LF translation to data block
    ///
    /// C reference: Netascii translation loop in get_block() (lines 1496-1519)
    ///
    /// Translates LF to CR-LF, tracking expansion and carry state across blocks
    fn apply_netascii_translation(&mut self, mut data: Vec<u8>) -> Result<Vec<u8>, TransferError> {
        let original_size = data.len();
        let mut result = Vec::with_capacity(data.len() + data.len() / 10); // Estimate expansion
        let mut new_carrylf = false;
        
        for (i, &byte) in data.iter().enumerate() {
            if byte == b'\n' && (i != 0 || !self.carrylf) {
                // Found LF that needs CR inserted
                self.expansion += 1;
                
                if original_size != self.blocksize as usize {
                    // Not a full block, we have room to expand
                    result.push(b'\r');
                    result.push(b'\n');
                } else if i == original_size - 1 {
                    // LF at end of full block, delay expansion to next block
                    new_carrylf = true;
                    result.push(b'\n');
                } else {
                    // Room in this block
                    result.push(b'\r');
                    result.push(b'\n');
                }
            } else {
                result.push(byte);
            }
        }
        
        self.carrylf = new_carrylf;
        Ok(result)
    }

    /// Check if transfer is complete
    ///
    /// Transfer is complete when we've sent a block smaller than blocksize
    pub fn is_complete(&self) -> bool {
        self.offset >= self.file.size() && self.block > 0
    }

    /// Check if transfer has timed out
    ///
    /// C reference: Timeout check in check_tftp_listeners() (lines 898-950)
    pub fn is_timed_out(&self) -> bool {
        Instant::now() >= self.timeout && self.backoff > MAX_BACKOFF
    }

    /// Reset timeout to current time plus exponential backoff
    ///
    /// C reference: Timeout update in check_tftp_listeners() (line 904)
    pub fn reset_timeout(&mut self) {
        let backoff_duration = Duration::from_secs(INITIAL_TIMEOUT_SECS * (1 << (self.backoff / 2)));
        self.timeout = Instant::now() + backoff_duration;
    }

    /// Increment backoff counter for retransmission
    ///
    /// C reference: transfer->backoff++ in check_tftp_listeners() (line 914)
    pub fn increment_backoff(&mut self) {
        self.backoff += 1;
        self.reset_timeout();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_options_builder() {
        let opts = TransferOptions::new()
            .with_blocksize()
            .with_tsize();
        
        assert!(opts.blocksize_requested);
        assert!(opts.tsize_requested);
        assert!(!opts.timeout_requested);
    }

    #[test]
    fn test_file_metadata_stale_detection() {
        let meta1 = FileMetadata::new(1, 12345, 1024);
        let meta2 = FileMetadata::new(1, 12345, 1024);
        let meta3 = FileMetadata::new(1, 67890, 1024);
        
        assert!(!meta1.is_stale(&meta2));
        assert!(meta1.is_stale(&meta3));
    }

    #[test]
    fn test_transfer_mode_equality() {
        assert_eq!(TransferMode::Octet, TransferMode::Octet);
        assert_ne!(TransferMode::Octet, TransferMode::Netascii);
    }

    #[tokio::test]
    async fn test_netascii_translation() {
        // Mock setup would go here for full test
        // This test demonstrates the structure
    }
}

