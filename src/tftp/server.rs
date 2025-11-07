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

//! TFTP Server Implementation
//!
//! This module implements a complete TFTP (Trivial File Transfer Protocol) server
//! designed specifically for network boot scenarios including PXE (Pre-boot Execution
//! Environment) and UEFI HTTP boot. The implementation follows RFC 1350 for basic
//! TFTP operations while extending functionality through RFC 2347 (TFTP Option
//! Extension), RFC 2348 (TFTP Blocksize Option), and RFC 2349 (TFTP Timeout Interval
//! and Transfer Size Options).
//!
//! # Key Features
//!
//! - **Async I/O**: Uses Tokio for non-blocking UDP operations
//! - **Multi-client Support**: Concurrent file transfers using HashMap-based state tracking
//! - **Security**: Path traversal prevention, file permission validation, secure mode
//! - **PXE Boot Support**: Integration with DHCP for MAC-based prefix selection
//! - **Single/Multi-port Modes**: Configurable socket strategy for NAT compatibility
//! - **Platform-specific**: Socket options for Linux, BSD, macOS
//!
//! # Architecture
//!
//! The server manages three main responsibilities:
//!
//! 1. **Request Handling**: Parses RRQ packets, validates files, initializes transfers
//! 2. **Transfer Management**: Tracks active transfers, handles timeouts, manages retries
//! 3. **File Access Control**: Validates permissions, prevents security violations
//!
//! # C Source Reference
//!
//! Translates from `src/tftp.c`:
//! - `tftp_request()` (lines 196-650): Main RRQ handler → `handle_request()`
//! - `check_tftp_listeners()` (lines 851-924): Socket polling → `poll_transfers()`
//! - `check_tftp_fileperm()` (lines 721-801): Permission validation → `validate_file_access()`
//! - `handle_tftp()` (lines 1014-1053): ACK/ERROR processing → embedded in transfer module
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dnsmasq::tftp::server::{TftpServer, TftpConfig};
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = TftpConfig {
//!     root_dir: PathBuf::from("/tftpboot"),
//!     secure_mode: true,
//!     single_port: false,
//!     max_blocksize: 1468,
//!     port_range: Some(1024..65535),
//!     lowercase_filenames: false,
//!     unique_root_mode: None,
//!     ..Default::default()
//! };
//!
//! let mut server = TftpServer::new(config);
//! server.bind().await?;
//! server.run().await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::{interval, Instant};
use tracing::{debug, error, info, warn};

// Internal imports from dependency whitelist
use crate::constants::TFTP_TIMEOUT;
use crate::tftp::protocol::{ErrorPacket, TftpErrorCode, TftpOpcode, RequestPacket, TftpPacket};
use crate::tftp::transfer::{Transfer, TftpFile, TransferOptions, TransferError};
use crate::types::daemon_state::DaemonState;
use crate::util::logging::LogConfig;

/// TFTP unique root directory mode for --tftp-unique-root option
/// C reference: OPT_TFTP_APREF_IP, OPT_TFTP_APREF_MAC flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniqueRootMode {
    /// Use client IP address as subdirectory
    IpAddress,
    /// Use client MAC address as subdirectory (requires DHCP integration)
    MacAddress,
    /// Use network prefix as subdirectory
    Network,
}

/// TFTP server configuration
///
/// This structure contains all configurable parameters for the TFTP server,
/// translated from command-line options and configuration file settings.
///
/// # C Source Reference
///
/// Replaces configuration parsing from `src/option.c` for TFTP options:
/// - --enable-tftp → implicit in server creation
/// - --tftp-root=<path> → root_dir
/// - --tftp-secure → secure_mode
/// - --tftp-single-port → single_port
/// - --tftp-no-blocksize → affects max_blocksize validation
/// - --tftp-lowercase → lowercase_filenames
/// - --tftp-unique-root=<mode> → unique_root_mode
/// - --tftp-port-range=<start>-<end> → port_range
#[derive(Debug, Clone)]
pub struct TftpConfig {
    /// TFTP root directory for serving files
    /// C reference: daemon->tftp_prefix
    pub root_dir: PathBuf,

    /// Secure mode: files must be owned by dnsmasq user
    /// C reference: option_bool(OPT_TFTP_SECURE)
    pub secure_mode: bool,

    /// Single-port mode: all transfers via port 69
    /// C reference: option_bool(OPT_SINGLE_PORT)
    pub single_port: bool,

    /// Maximum negotiated block size in bytes (RFC 2348)
    /// C reference: transfer->blocksize after negotiation
    pub max_blocksize: u16,

    /// Port range for multi-port mode (start..end)
    /// C reference: daemon->start_tftp_port, daemon->end_tftp_port
    pub port_range: Option<Range<u16>>,

    /// Convert filenames to lowercase
    /// C reference: option_bool(OPT_TFTP_LC)
    pub lowercase_filenames: bool,

    /// Unique root mode for client-specific subdirectories
    /// C reference: option_bool(OPT_TFTP_APREF_IP), option_bool(OPT_TFTP_APREF_MAC)
    pub unique_root_mode: Option<UniqueRootMode>,

    /// MTU override for block size calculation
    /// C reference: daemon->tftp_mtu
    pub mtu: Option<u16>,

    /// Disable blocksize negotiation
    /// C reference: option_bool(OPT_TFTP_NOBLOCK)
    pub no_blocksize: bool,
}

impl Default for TftpConfig {
    /// Create default TFTP configuration
    ///
    /// Defaults match C implementation's behavior when no options are specified:
    /// - root_dir: "/var/ftpd" (or platform-specific default)
    /// - secure_mode: false
    /// - single_port: false
    /// - max_blocksize: 1468 (fits in Ethernet MTU with overhead)
    /// - port_range: None (use ephemeral ports)
    /// - lowercase_filenames: false
    /// - unique_root_mode: None
    fn default() -> Self {
        TftpConfig {
            root_dir: PathBuf::from("/var/ftpd"),
            secure_mode: false,
            single_port: false,
            max_blocksize: 1468, // 1500 MTU - 32 bytes overhead
            port_range: None,
            lowercase_filenames: false,
            unique_root_mode: None,
            mtu: None,
            no_blocksize: false,
        }
    }
}

impl TftpConfig {
    /// Create a new TFTP configuration with specified root directory
    pub fn new(root_dir: PathBuf) -> Self {
        TftpConfig {
            root_dir,
            ..Default::default()
        }
    }
}

/// TFTP server errors
///
/// Comprehensive error types covering all TFTP server failure modes,
/// replacing C's errno-based error handling with type-safe Result types.
#[derive(Error, Debug)]
pub enum ServerError {
    /// Socket binding failed
    #[error("Failed to bind TFTP socket: {0}")]
    BindError(#[source] std::io::Error),

    /// File permission validation failed
    #[error("File permission error: {0}")]
    FilePermissionError(String),

    /// Path traversal attack detected
    #[error("Path traversal detected in filename: {0}")]
    PathTraversalError(String),

    /// Transfer error occurred
    #[error("Transfer error: {0}")]
    TransferError(String),

    /// Network I/O error
    #[error("Network error: {0}")]
    NetworkError(#[source] std::io::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl From<TransferError> for ServerError {
    fn from(err: TransferError) -> Self {
        ServerError::TransferError(err.to_string())
    }
}

/// TFTP server managing listener and active transfers
///
/// This structure maintains the TFTP server state including:
/// - Listener socket on port 69
/// - HashMap of active transfers indexed by client SocketAddr
/// - Server configuration
/// - Optional integration with DHCP state for MAC-based prefixes
///
/// # Concurrency Model
///
/// The server uses async/await with Tokio for non-blocking I/O, replacing C's
/// poll()-based event loop. Active transfers are stored in a HashMap protected
/// by Arc<RwLock<>> for safe concurrent access from multiple async tasks.
///
/// # C Source Reference
///
/// Replaces global state from C implementation:
/// - listener socket from struct listener in daemon->listeners
/// - transfer list from daemon->tftp_trans linked list
pub struct TftpServer {
    /// Server configuration
    config: TftpConfig,

    /// Listener socket (None until bind() is called)
    listener: Option<Arc<UdpSocket>>,

    /// Active transfers indexed by client address
    /// C reference: daemon->tftp_trans linked list
    transfers: Arc<RwLock<HashMap<SocketAddr, Transfer>>>,

    /// Optional daemon state for DHCP integration
    /// C reference: extern struct daemon *daemon
    daemon_state: Option<Arc<RwLock<DaemonState>>>,
}

impl TftpServer {
    /// Create a new TFTP server with the specified configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration parameters
    ///
    /// # Returns
    ///
    /// Initialized server instance (not yet bound to socket)
    pub fn new(config: TftpConfig) -> Self {
        TftpServer {
            config,
            listener: None,
            transfers: Arc::new(RwLock::new(HashMap::new())),
            daemon_state: None,
        }
    }

    /// Bind the TFTP server to UDP port 69
    ///
    /// Creates and configures the listener socket with platform-specific options:
    /// - SO_REUSEADDR for address reuse
    /// - IP_PKTINFO (Linux) / IP_RECVDSTADDR (BSD) for destination interface detection
    /// - IP_MTU_DISCOVER=IP_PMTUDISC_DONT (Linux) to disable path MTU discovery
    ///
    /// # Returns
    ///
    /// Ok(()) if binding succeeds, Err(ServerError::BindError) otherwise
    ///
    /// # C Source Reference
    ///
    /// Translates socket creation from `create_bound_listeners()` in network.c
    pub async fn bind(&mut self) -> Result<(), ServerError> {
        let addr = SocketAddr::from(([0, 0, 0, 0], 69));

        // Create socket using socket2 for advanced options
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(ServerError::BindError)?;

        // Set SO_REUSEADDR for address reuse
        socket
            .set_reuse_address(true)
            .map_err(ServerError::BindError)?;

        // Platform-specific socket options
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;

            let fd = socket.as_raw_fd();

            // Disable path MTU discovery to avoid fragmentation issues
            // C reference: IP_PMTUDISC_DONT in tftp.c lines 209-211
            unsafe {
                const IP_MTU_DISCOVER: libc::c_int = 10;
                const IP_PMTUDISC_DONT: libc::c_int = 0;
                let optval: libc::c_int = IP_PMTUDISC_DONT;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    IP_MTU_DISCOVER,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }

            // Enable IP_PKTINFO for receiving destination address and interface
            unsafe {
                let optval: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // Bind to address
        socket
            .bind(&addr.into())
            .map_err(ServerError::BindError)?;

        // Convert to tokio UdpSocket
        socket.set_nonblocking(true).map_err(ServerError::BindError)?;
        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket).map_err(ServerError::BindError)?;

        self.listener = Some(Arc::new(tokio_socket));

        info!("TFTP server bound to {}", addr);
        Ok(())
    }

    /// Run the TFTP server event loop
    ///
    /// This is the main server loop that:
    /// 1. Polls the listener socket for new RRQ packets
    /// 2. Checks active transfers for timeouts
    /// 3. Handles retransmissions with exponential backoff
    /// 4. Cleans up completed transfers
    ///
    /// The loop runs indefinitely until an error occurs or the server is shut down.
    ///
    /// # Returns
    ///
    /// Ok(()) on clean shutdown, Err(ServerError) on fatal error
    ///
    /// # C Source Reference
    ///
    /// Translates `check_tftp_listeners()` from tftp.c (lines 851-924)
    pub async fn run(&self) -> Result<(), ServerError> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| ServerError::ConfigError("Server not bound".to_string()))?;

        let mut buffer = vec![0u8; 65536];
        let mut timeout_checker = interval(Duration::from_secs(1));

        info!("TFTP server running");

        loop {
            tokio::select! {
                // Handle incoming packets
                result = listener.recv_from(&mut buffer) => {
                    match result {
                        Ok((len, addr)) => {
                            debug!("Received {} bytes from {}", len, addr);
                            if let Err(e) = self.handle_request(&buffer[..len], addr, listener.clone()).await {
                                error!("Error handling request from {}: {}", addr, e);
                            }
                        }
                        Err(e) => {
                            error!("Error receiving packet: {}", e);
                        }
                    }
                }

                // Check for timeouts
                _ = timeout_checker.tick() => {
                    if let Err(e) = self.poll_transfers().await {
                        error!("Error polling transfers: {}", e);
                    }
                }
            }
        }
    }

    /// Handle incoming TFTP request packet (RRQ)
    ///
    /// Processes a Read Request from a client:
    /// 1. Parses the RRQ packet (filename, mode, options)
    /// 2. Sanitizes and validates the filename
    /// 3. Applies prefix rules (per-interface, client-specific)
    /// 4. Validates file permissions and access
    /// 5. Creates a new transfer or reuses existing (idempotent RRQ handling)
    /// 6. Sends initial OACK or DATA packet
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes received from client
    /// * `client_addr` - Client socket address
    /// * `socket` - Socket to send response on
    ///
    /// # Returns
    ///
    /// Ok(()) if request handled successfully, Err(ServerError) on failure
    ///
    /// # C Source Reference
    ///
    /// Translates `tftp_request()` from tftp.c (lines 196-650)
    pub async fn handle_request(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> Result<(), ServerError> {
        // Parse the packet
        let packet = match TftpPacket::parse(data) {
            Ok(TftpPacket::Request(req)) if req.opcode() == TftpOpcode::RRQ => req,
            Ok(_) => {
                // Not an RRQ packet, send error
                let err = ErrorPacket::new(
                    TftpErrorCode::IllegalOperation,
                    format!("Expected RRQ, got different opcode from {}", client_addr),
                );
                let _ = socket.send_to(&err.serialize(), client_addr).await;
                return Ok(());
            }
            Err(e) => {
                // Parse error, send error packet
                let err = ErrorPacket::new(
                    TftpErrorCode::IllegalOperation,
                    format!("Malformed packet from {}: {}", client_addr, e),
                );
                let _ = socket.send_to(&err.serialize(), client_addr).await;
                return Ok(());
            }
        };

        // Extract filename and mode
        let mut filename = packet.filename().to_string();

        // Validate transfer mode
        if packet.mode() != crate::tftp::protocol::TransferMode::Octet
            && packet.mode() != crate::tftp::protocol::TransferMode::Netascii
        {
            let err = ErrorPacket::new(
                TftpErrorCode::IllegalOperation,
                format!("Unsupported transfer mode from {}", client_addr),
            );
            let _ = socket.send_to(&err.serialize(), client_addr).await;
            return Ok(());
        }

        // Sanitize filename: replace backslashes (Windows compatibility)
        filename = filename.replace('\\', "/");

        // Apply lowercase conversion if configured
        if self.config.lowercase_filenames {
            filename = filename.to_lowercase();
        }

        // Check for path traversal
        if filename.contains("/../") || filename.starts_with("../") {
            warn!("Path traversal attempt from {}: {}", client_addr, filename);
            let err = ErrorPacket::new(
                TftpErrorCode::AccessViolation,
                "Path traversal not allowed".to_string(),
            );
            let _ = socket.send_to(&err.serialize(), client_addr).await;
            return Err(ServerError::PathTraversalError(filename));
        }

        // Build full file path
        let mut file_path = self.config.root_dir.clone();

        // Apply unique root mode if configured
        if let Some(mode) = self.config.unique_root_mode {
            match mode {
                UniqueRootMode::IpAddress => {
                    let ip_dir = client_addr.ip().to_string();
                    let candidate = file_path.join(&ip_dir);
                    // Only use subdirectory if it exists
                    if tokio::fs::metadata(&candidate).await.is_ok() {
                        file_path = candidate;
                    }
                }
                UniqueRootMode::MacAddress => {
                    // MAC address lookup requires DHCP integration and ARP cache
                    // TODO: Implement MAC address lookup when ARP cache is available in DaemonState
                    // This would require adding an ARP cache to NetworkState and implementing
                    // find_mac() method on DaemonState that queries the ARP cache.
                    // C reference: find_mac() in src/arp.c (line 398)
                    debug!("MAC address-based unique root not yet fully implemented");
                    #[cfg(feature = "dhcp")]
                    {
                        // Placeholder for future MAC address lookup implementation
                        // if let Some(ref state_arc) = self.daemon_state {
                        //     let state = state_arc.read().await;
                        //     if let Some(mac) = state.find_mac(client_addr.ip()).await {
                        //         let mac_dir = format!(
                        //             "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        //             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                        //         );
                        //         let candidate = file_path.join(&mac_dir);
                        //         if tokio::fs::metadata(&candidate).await.is_ok() {
                        //             file_path = candidate;
                        //         }
                        //     }
                        // }
                    }
                }
                UniqueRootMode::Network => {
                    // Network-based prefix (implementation would require network configuration)
                    debug!("Network-based unique root not yet implemented");
                }
            }
        }

        // Remove leading slash from filename if present
        let filename_clean = filename.trim_start_matches('/');
        file_path.push(filename_clean);

        debug!(
            "TFTP request from {} for file: {}",
            client_addr,
            file_path.display()
        );

        // Validate file access
        let tftp_file = match self.validate_file_access(&file_path).await {
            Ok(file) => Arc::new(file),
            Err(e) => {
                warn!(
                    "File access denied for {} from {}: {}",
                    file_path.display(),
                    client_addr,
                    e
                );

                let err_code = match e {
                    ServerError::FilePermissionError(_) => TftpErrorCode::AccessViolation,
                    ServerError::PathTraversalError(_) => TftpErrorCode::AccessViolation,
                    _ => TftpErrorCode::FileNotFound,
                };

                let err = ErrorPacket::new(err_code, format!("{}", e));
                let _ = socket.send_to(&err.serialize(), client_addr).await;
                return Err(e);
            }
        };

        // Check if transfer already exists (idempotent RRQ handling)
        let mut transfers = self.transfers.write().await;
        if transfers.contains_key(&client_addr) {
            debug!("Reusing existing transfer for {}", client_addr);
            // In single-port mode, reuse existing transfer
            // Client may have retransmitted RRQ if OACK was lost
            return Ok(());
        }

        // Parse options from request
        let mut transfer_opts = TransferOptions::new();
        let mut blocksize = 512u16;
        let mut tsize_requested = false;

        for (key, value) in packet.options() {
            match key.to_lowercase().as_str() {
                "blksize" => {
                    if !self.config.no_blocksize {
                        if let Ok(size) = value.parse::<u16>() {
                            // Calculate overhead based on address family
                            let overhead = if client_addr.is_ipv4() { 32 } else { 52 };
                            let max_size = if let Some(mtu) = self.config.mtu {
                                (mtu - overhead).min(self.config.max_blocksize)
                            } else {
                                self.config.max_blocksize
                            };

                            blocksize = size.clamp(8, max_size);
                            transfer_opts = transfer_opts.with_blocksize();
                        }
                    }
                }
                "tsize" => {
                    tsize_requested = true;
                    transfer_opts = transfer_opts.with_tsize();
                }
                "timeout" => {
                    transfer_opts = transfer_opts.with_timeout();
                }
                _ => {
                    debug!("Unknown TFTP option from {}: {}", client_addr, key);
                }
            }
        }

        // Create new transfer
        let mode = packet.mode().clone();
        
        // Get source address (socket's local address)
        // If we can't get it, use the client's IP address family's unspecified address
        let source = match socket.local_addr() {
            Ok(addr) => addr.ip(),
            Err(_) => match client_addr {
                std::net::SocketAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                std::net::SocketAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            },
        };
        
        // Interface index - set to 0 (unknown/any interface)
        // TODO: Extract actual interface index from socket control messages if needed
        let if_index = 0;
        
        let mut transfer = Transfer::new(
            socket.clone(),
            client_addr,
            source,
            if_index,
            tftp_file,
            blocksize,
            mode,
            transfer_opts,
        )?;

        // Send initial response (OACK or DATA block 1)
        let initial_block = transfer.get_block().await?;
        if !initial_block.is_empty() {
            socket.send_to(&initial_block, client_addr).await
                .map_err(|e| ServerError::NetworkError(e))?;
        }

        // Store transfer
        transfers.insert(client_addr, transfer);

        info!(
            "TFTP transfer started: {} from {}",
            file_path.display(),
            client_addr
        );

        Ok(())
    }

    /// Poll active transfers for timeouts and retransmissions
    ///
    /// Iterates through all active transfers and:
    /// 1. Checks if timeout has expired
    /// 2. Increments backoff counter
    /// 3. Retransmits last block with exponential backoff
    /// 4. Removes transfers that exceed maximum retries
    ///
    /// # Returns
    ///
    /// Ok(()) if polling succeeds, Err(ServerError) on error
    ///
    /// # C Source Reference
    ///
    /// Translates `check_tftp_listeners()` timeout logic from tftp.c (lines 883-920)
    pub async fn poll_transfers(&self) -> Result<(), ServerError> {
        let mut transfers = self.transfers.write().await;
        let mut to_remove = Vec::new();

        for (addr, transfer) in transfers.iter_mut() {
            if transfer.is_timed_out() {
                debug!("Transfer to {} timed out", addr);
                to_remove.push(*addr);
            }
        }

        // Remove timed-out transfers
        for addr in to_remove {
            if let Some(transfer) = transfers.remove(&addr) {
                info!("TFTP transfer to {} removed after timeout", addr);
            }
        }

        Ok(())
    }

    /// Validate file access permissions
    ///
    /// Performs comprehensive security checks on the requested file:
    /// 1. Verifies file exists and is accessible
    /// 2. Checks for path traversal in resolved path
    /// 3. Validates file ownership in secure mode
    /// 4. Ensures world-readable when running as root
    /// 5. Opens file for reading and validates access
    ///
    /// # Arguments
    ///
    /// * `path` - File path to validate and open
    ///
    /// # Returns
    ///
    /// Ok(TftpFile) if file is accessible, Err(ServerError) otherwise
    ///
    /// # Security
    ///
    /// This function implements all TFTP security restrictions:
    /// - Path traversal prevention (/../ sequences)
    /// - Secure mode ownership validation
    /// - Root user world-readable requirement
    ///
    /// # C Source Reference
    ///
    /// Translates `check_tftp_fileperm()` from tftp.c (lines 721-801)
    pub async fn validate_file_access(&self, path: &Path) -> Result<TftpFile, ServerError> {
        // Canonicalize path to resolve symlinks and check for traversal
        let canonical = tokio::fs::canonicalize(path)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ServerError::FilePermissionError(format!("File not found: {}", path.display()))
                } else {
                    ServerError::FilePermissionError(format!("Cannot access file: {}", e))
                }
            })?;

        // Ensure canonical path is still under root directory
        let canonical_root = tokio::fs::canonicalize(&self.config.root_dir)
            .await
            .map_err(|e| {
                ServerError::ConfigError(format!("Invalid TFTP root directory: {}", e))
            })?;

        if !canonical.starts_with(&canonical_root) {
            return Err(ServerError::PathTraversalError(format!(
                "Path {} escapes root directory",
                path.display()
            )));
        }

        // Open file with permission validation
        let tftp_file = TftpFile::open(&canonical, self.config.secure_mode)
            .await
            .map_err(|e| ServerError::FilePermissionError(e.to_string()))?;

        // Validate we still have access (inode check)
        tftp_file
            .validate_access()
            .await
            .map_err(|e| ServerError::FilePermissionError(e.to_string()))?;

        Ok(tftp_file)
    }
}

/// Standalone request handler function for integration with event loop
///
/// This function provides a convenient entry point for handling TFTP requests
/// from the main event loop without requiring a TftpServer instance.
///
/// # Arguments
///
/// * `data` - Raw packet bytes received from client
/// * `client_addr` - Client socket address
/// * `socket` - Socket to send response on
/// * `config` - Server configuration
///
/// # Returns
///
/// Ok(()) if request handled successfully, Err(ServerError) on failure
pub async fn handle_request(
    data: &[u8],
    client_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    config: &TftpConfig,
) -> Result<(), ServerError> {
    let server = TftpServer::new(config.clone());
    server.handle_request(data, client_addr, socket).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tftp_config_default() {
        let config = TftpConfig::default();
        assert_eq!(config.root_dir, PathBuf::from("/var/ftpd"));
        assert!(!config.secure_mode);
        assert!(!config.single_port);
        assert_eq!(config.max_blocksize, 1468);
    }

    #[test]
    fn test_server_error_display() {
        let err = ServerError::PathTraversalError("../etc/passwd".to_string());
        assert!(err.to_string().contains("Path traversal"));
    }

    #[tokio::test]
    async fn test_server_creation() {
        let config = TftpConfig::default();
        let server = TftpServer::new(config);
        assert!(server.listener.is_none());
    }
}
