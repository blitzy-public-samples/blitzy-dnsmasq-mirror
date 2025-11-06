// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later

//! Comprehensive error types for dnsmasq Rust implementation
//!
//! This module defines all error types used throughout the dnsmasq codebase,
//! replacing C's errno-based error handling with Rust's type-safe Result pattern.
//! All errors use the thiserror crate for automatic Error trait implementation
//! with proper Display, Debug, and source error chaining.
//!
//! # Error Hierarchy
//!
//! - `DnsmasqError` - Top-level error enum wrapping all subsystem errors
//! - `DnsError` - DNS protocol, caching, and forwarding errors
//! - `DhcpError` - DHCPv4/v6 server and lease management errors
//! - `NetworkError` - Socket operations and network I/O errors
//! - `ConfigError` - Configuration parsing and validation errors
//! - `SystemError` - Privilege dropping, daemonization, and system calls
//! - `TftpError` - TFTP server and file transfer errors
//! - `LogError` - Logging subsystem errors
//! - `DnssecError` - DNSSEC validation and cryptographic errors
//! - `AuthError` - Authoritative DNS server errors
//!
//! # Type-Safe Error Propagation
//!
//! The C implementation uses return codes and errno for error handling:
//! ```c
//! // C error handling pattern (unsafe)
//! if (bind(fd, addr, addrlen) < 0) {
//!     my_syslog(LOG_ERR, "bind failed: %s", strerror(errno));
//!     return -1;
//! }
//! ```
//!
//! The Rust implementation uses Result types with detailed error context:
//! ```rust,ignore
//! // Rust error handling pattern (type-safe)
//! socket.bind(addr)
//!     .map_err(|e| NetworkError::BindFailed {
//!         address: addr.to_string(),
//!         source: e,
//!     })?;
//! ```
//!
//! # Error Context
//!
//! All error variants include contextual information to aid debugging:
//! - Source errors are preserved through error chains
//! - Relevant values (addresses, file paths, option names) are captured
//! - Human-readable messages explain the failure
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use crate::types::errors::{DnsmasqResult, DnsmasqError, NetworkError};
//!
//! fn bind_dns_socket(port: u16) -> DnsmasqResult<TcpListener> {
//!     let addr = SocketAddr::from(([0, 0, 0, 0], port));
//!     TcpListener::bind(addr)
//!         .map_err(|e| NetworkError::BindFailed {
//!             address: addr.to_string(),
//!             source: e,
//!         })
//!         .map_err(DnsmasqError::Network)
//! }
//! ```

use std::io;
use thiserror::Error;

/// Main error type for dnsmasq operations
///
/// This is the top-level error enum that wraps all subsystem-specific errors.
/// It provides a unified error type for the entire application while preserving
/// detailed error information from specific subsystems.
///
/// # Error Chaining
///
/// All variants wrap subsystem-specific error types, creating an error chain
/// that can be traversed using the `source()` method from the Error trait.
///
/// # Conversion
///
/// Subsystem errors automatically convert to `DnsmasqError` via `From` implementations,
/// enabling the `?` operator for seamless error propagation across subsystem boundaries.
#[derive(Debug, Error)]
pub enum DnsmasqError {
    /// DNS subsystem error (protocol parsing, caching, forwarding)
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),

    /// DHCP subsystem error (lease management, packet handling)
    #[error("DHCP error: {0}")]
    Dhcp(#[from] DhcpError),

    /// Network I/O error (socket operations, packet transmission)
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Configuration error (parsing, validation)
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// System error (privilege dropping, daemonization, signals)
    #[error("System error: {0}")]
    System(#[from] SystemError),

    /// TFTP server error (file transfers, protocol handling)
    #[error("TFTP error: {0}")]
    Tftp(#[from] TftpError),

    /// Logging subsystem error
    #[error("Logging error: {0}")]
    Log(#[from] LogError),

    /// DNSSEC validation error
    #[error("DNSSEC error: {0}")]
    Dnssec(#[from] DnssecError),

    /// Authoritative DNS error
    #[error("Authoritative DNS error: {0}")]
    Auth(#[from] AuthError),
}

/// Result type alias for dnsmasq operations
///
/// This is a convenience alias for Result<T, DnsmasqError> used throughout
/// the codebase to reduce boilerplate and improve readability.
///
/// # Examples
///
/// ```rust,ignore
/// fn process_query(query: &[u8]) -> DnsmasqResult<DnsResponse> {
///     // Function implementation
/// }
/// ```
pub type DnsmasqResult<T> = Result<T, DnsmasqError>;

/// DNS subsystem errors
///
/// Covers errors in DNS protocol parsing, caching, query forwarding,
/// and response handling. These errors replace C's return code patterns
/// in rfc1035.c, cache.c, forward.c, and related DNS modules.
///
/// # C Error Pattern Replaced
///
/// C code used return codes and global errno:
/// ```c
/// // C pattern (from rfc1035.c)
/// if (extract_name(header, plen, &p, name, 1, 4) < 0)
///     return 0; // Generic failure
/// ```
///
/// Rust uses typed errors with context:
/// ```rust,ignore
/// extract_name(header, &mut offset, name)
///     .map_err(|_| DnsError::ProtocolError {
///         message: "Invalid name compression".into(),
///     })?;
/// ```
#[derive(Debug, Error)]
pub enum DnsError {
    /// DNS protocol violation or malformed packet
    #[error("DNS protocol error: {message}")]
    ProtocolError {
        /// Description of the protocol violation
        message: String,
    },

    /// DNS cache operation failed
    #[error("DNS cache error: {message}")]
    CacheError {
        /// Description of the cache failure
        message: String,
    },

    /// DNS query forwarding failed
    #[error("DNS forwarding error: {message}")]
    ForwardError {
        /// Description of the forwarding failure
        message: String,
    },

    /// DNS name compression error
    #[error("DNS compression error: {message}")]
    CompressionError {
        /// Description of the compression issue
        message: String,
    },

    /// Invalid DNS query received
    #[error("Invalid DNS query: {message}")]
    InvalidQuery {
        /// Description of query validation failure
        message: String,
    },

    /// Invalid DNS response from upstream
    #[error("Invalid DNS response: {message}")]
    InvalidResponse {
        /// Description of response validation failure
        message: String,
    },

    /// DNS packet exceeds maximum size (512 bytes for UDP, or EDNS limit)
    #[error("DNS packet too large: {size} bytes exceeds limit of {limit} bytes")]
    PacketTooLarge {
        /// Actual packet size
        size: usize,
        /// Maximum allowed size
        limit: usize,
    },

    /// DNS query timeout expired
    #[error("DNS query timeout after {timeout_ms}ms")]
    Timeout {
        /// Timeout duration in milliseconds
        timeout_ms: u64,
    },
}

/// DHCP subsystem errors
///
/// Covers errors in DHCPv4/v6 packet processing, lease management,
/// address allocation, and state machine transitions. These replace
/// C's return code patterns in dhcp.c, dhcp6.c, rfc2131.c, rfc3315.c,
/// and lease.c.
///
/// # DHCP State Machine Errors
///
/// The C implementation uses implicit state transitions with minimal
/// error handling. Rust enforces explicit state validation:
///
/// ```c
/// // C pattern (from dhcp.c)
/// if (!(lease = lease_find_by_client(mess->chaddr, ...)))
///     return 0; // Silent failure
/// ```
///
/// ```rust,ignore
/// // Rust pattern with explicit error
/// let lease = lease_db.find_by_client(&client_mac)
///     .ok_or(DhcpError::LeaseNotFound { 
///         client_mac: client_mac.to_string() 
///     })?;
/// ```
#[derive(Debug, Error)]
pub enum DhcpError {
    /// DHCP packet format violation
    #[error("Invalid DHCP packet: {message}")]
    InvalidPacket {
        /// Description of packet validation failure
        message: String,
    },

    /// No IP address available in configured pools
    #[error("No available IP address in pool for {client_id}")]
    NoAvailableAddress {
        /// Client identifier (MAC or DUID)
        client_id: String,
    },

    /// Lease not found in database
    #[error("Lease not found for {identifier}")]
    LeaseNotFound {
        /// Client or lease identifier
        identifier: String,
    },

    /// Invalid DHCP option encoding or value
    #[error("Invalid DHCP option {option_code}: {message}")]
    InvalidOption {
        /// DHCP option code
        option_code: u8,
        /// Description of option error
        message: String,
    },

    /// Lease database I/O or corruption error
    #[error("Lease database error: {message}")]
    DatabaseError {
        /// Description of database failure
        message: String,
        /// Underlying I/O error if applicable
        #[source]
        source: Option<io::Error>,
    },

    /// DHCP state machine violation
    #[error("DHCP state machine error: {message}")]
    StateMachineError {
        /// Description of state transition failure
        message: String,
    },

    /// ICMP ping check failed (address in use)
    #[error("Ping check failed for {address}: address appears to be in use")]
    PingCheckFailed {
        /// IP address that responded to ping
        address: String,
    },

    /// DHCP script execution failed
    #[error("Script execution failed: {script_path}")]
    ScriptExecutionError {
        /// Path to the script that failed
        script_path: String,
        /// Underlying error
        #[source]
        source: io::Error,
    },
}

/// Network I/O errors
///
/// Covers socket operations, packet transmission/reception, interface
/// enumeration, and address resolution. These replace C's errno-based
/// error handling in network.c, netlink.c, bpf.c, and socket operations
/// throughout the codebase.
///
/// # Socket Error Handling
///
/// C code checks return values and uses strerror(errno):
/// ```c
/// // C pattern (from network.c)
/// if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
///     my_syslog(LOG_ERR, "socket: %s", strerror(errno));
///     return -1;
/// }
/// ```
///
/// Rust preserves the underlying error with type safety:
/// ```rust,ignore
/// let socket = UdpSocket::bind(addr)
///     .map_err(|e| NetworkError::SocketCreationFailed {
///         socket_type: "UDP".into(),
///         source: e,
///     })?;
/// ```
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Failed to create socket
    #[error("Failed to create {socket_type} socket")]
    SocketCreationFailed {
        /// Socket type (TCP, UDP, RAW)
        socket_type: String,
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Failed to bind socket to address
    #[error("Failed to bind to {address}")]
    BindFailed {
        /// Address that failed to bind
        address: String,
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Failed to send packet
    #[error("Failed to send packet to {destination}")]
    SendFailed {
        /// Destination address
        destination: String,
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Failed to receive packet
    #[error("Failed to receive packet")]
    ReceiveFailed {
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Failed to enumerate network interfaces
    #[error("Failed to enumerate network interfaces")]
    InterfaceEnumerationFailed {
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Failed to resolve address
    #[error("Failed to resolve address: {address}")]
    AddressResolutionFailed {
        /// Address that failed to resolve
        address: String,
        /// Description of resolution failure
        message: String,
    },

    /// Connection failed or dropped
    #[error("Connection failed to {destination}")]
    ConnectionFailed {
        /// Destination address or hostname
        destination: String,
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Invalid network address format
    #[error("Invalid network address: {address}")]
    InvalidAddress {
        /// Invalid address string
        address: String,
        /// Description of validation failure
        message: String,
    },
}

/// Configuration parsing and validation errors
///
/// Covers errors in command-line argument parsing, configuration file
/// parsing, option validation, and configuration conflicts. These replace
/// C's die() calls and return code checks in option.c.
///
/// # Configuration Error Handling
///
/// C code calls die() on configuration errors (terminates process):
/// ```c
/// // C pattern (from option.c)
/// if (invalid_option)
///     die("invalid option: %s", option, EC_BADCONF);
/// ```
///
/// Rust returns detailed errors allowing graceful handling:
/// ```rust,ignore
/// parse_config_line(line)
///     .map_err(|_| ConfigError::ParseError {
///         line_number: lineno,
///         content: line.into(),
///         message: "Invalid syntax".into(),
///     })?;
/// ```
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Configuration file parse error
    #[error("Parse error at line {line_number}: {message}")]
    ParseError {
        /// Line number where error occurred
        line_number: usize,
        /// Content of the problematic line
        content: String,
        /// Description of parse failure
        message: String,
    },

    /// Unknown or unsupported configuration option
    #[error("Unknown option: {option}")]
    InvalidOption {
        /// Name of the invalid option
        option: String,
    },

    /// Invalid value for configuration option
    #[error("Invalid value for option '{option}': {message}")]
    InvalidValue {
        /// Option name
        option: String,
        /// Invalid value provided
        value: String,
        /// Description of validation failure
        message: String,
    },

    /// Required configuration option missing
    #[error("Missing required option: {option}")]
    MissingRequired {
        /// Name of the required option
        option: String,
    },

    /// Conflicting configuration options
    #[error("Conflicting options: {option1} and {option2} cannot be used together")]
    ConflictingOptions {
        /// First conflicting option
        option1: String,
        /// Second conflicting option
        option2: String,
    },

    /// Configuration file not found
    #[error("Configuration file not found: {path}")]
    FileNotFound {
        /// Path to missing configuration file
        path: String,
    },

    /// Permission denied reading configuration
    #[error("Permission denied: {path}")]
    PermissionDenied {
        /// Path with permission issue
        path: String,
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Configuration validation failed
    #[error("Validation failed: {message}")]
    ValidationFailed {
        /// Description of validation failure
        message: String,
    },
}

/// System operation errors
///
/// Covers privilege dropping, daemonization, PID file management,
/// signal handling, resource limits, and process spawning. These
/// replace C's errno-based handling in daemon.c and helper.c.
///
/// # Privilege Separation Errors
///
/// C code uses setuid/setgid with errno checking:
/// ```c
/// // C pattern (from daemon.c)
/// if (setuid(daemon->ent_pw->pw_uid) == -1)
///     die("failed to set userid: %s", strerror(errno), EC_MISC);
/// ```
///
/// Rust provides structured error context:
/// ```rust,ignore
/// nix::unistd::setuid(uid)
///     .map_err(|e| SystemError::PrivilegeDropFailed {
///         target_uid: uid.as_raw(),
///         source: e.into(),
///     })?;
/// ```
#[derive(Debug, Error)]
pub enum SystemError {
    /// Failed to drop privileges (setuid/setgid)
    #[error("Failed to drop privileges to uid={target_uid}, gid={target_gid}")]
    PrivilegeDropFailed {
        /// Target user ID
        target_uid: u32,
        /// Target group ID
        target_gid: u32,
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Failed to daemonize process
    #[error("Daemonization failed: {message}")]
    DaemonizationFailed {
        /// Description of daemonization failure
        message: String,
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// PID file operation failed
    #[error("PID file error: {path}")]
    PidFileError {
        /// Path to PID file
        path: String,
        /// Description of error
        message: String,
        /// Underlying OS error
        #[source]
        source: Option<io::Error>,
    },

    /// Signal handler installation failed
    #[error("Failed to install signal handler for {signal}")]
    SignalHandlerError {
        /// Signal name (SIGHUP, SIGTERM, etc.)
        signal: String,
        /// Underlying error
        #[source]
        source: io::Error,
    },

    /// Resource limit exceeded
    #[error("Resource limit exceeded: {resource}")]
    ResourceLimitExceeded {
        /// Resource type (file descriptors, memory, etc.)
        resource: String,
        /// Current limit value
        limit: u64,
    },

    /// Insufficient memory
    #[error("Insufficient memory: failed to allocate {size} bytes")]
    InsufficientMemory {
        /// Requested allocation size
        size: usize,
    },

    /// Failed to spawn child process
    #[error("Failed to spawn process: {command}")]
    ProcessSpawnFailed {
        /// Command that failed to spawn
        command: String,
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Filesystem operation failed
    #[error("Filesystem error: {operation} failed for {path}")]
    FileSystemError {
        /// Operation type (create, delete, rename, etc.)
        operation: String,
        /// File or directory path
        path: String,
        /// Underlying OS error
        #[source]
        source: io::Error,
    },
}

/// TFTP server errors
///
/// Covers TFTP protocol handling, file transfer operations, and
/// access control. These replace C's error handling in tftp.c.
///
/// # TFTP Error Codes
///
/// C uses TFTP protocol error codes directly:
/// ```c
/// // C pattern (from tftp.c)
/// len = tftp_err(ERR_NOTFOUND, packet, "File not found", file);
/// ```
///
/// Rust uses typed errors that can convert to protocol error codes:
/// ```rust,ignore
/// Err(TftpError::FileNotFound { 
///     filename: path.to_string() 
/// })
/// // Converted to TFTP ERROR packet with code 1
/// ```
#[derive(Debug, Error)]
pub enum TftpError {
    /// Requested file not found
    #[error("TFTP: File not found: {filename}")]
    FileNotFound {
        /// Name of requested file
        filename: String,
    },

    /// Access denied (permissions or security policy)
    #[error("TFTP: Access denied: {filename}")]
    AccessDenied {
        /// File path
        filename: String,
        /// Reason for denial
        reason: String,
    },

    /// Disk full or allocation failure
    #[error("TFTP: Disk full")]
    DiskFull {
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Illegal TFTP operation
    #[error("TFTP: Illegal operation: {message}")]
    IllegalOperation {
        /// Description of illegal operation
        message: String,
    },

    /// Unknown transfer ID (wrong port or session)
    #[error("TFTP: Unknown transfer ID")]
    UnknownTransferId,

    /// File already exists (for write operations)
    #[error("TFTP: File already exists: {filename}")]
    FileAlreadyExists {
        /// Name of existing file
        filename: String,
    },

    /// Transfer aborted by client or timeout
    #[error("TFTP: Transfer aborted: {reason}")]
    TransferAborted {
        /// Reason for abort
        reason: String,
    },

    /// Invalid TFTP packet format
    #[error("TFTP: Invalid packet: {message}")]
    InvalidPacket {
        /// Description of packet error
        message: String,
    },
}

/// Logging subsystem errors
///
/// Covers errors in log initialization, writing, rotation, and
/// queue management. These replace C's error handling in log.c.
///
/// # Async Logging Errors
///
/// C queues log messages and drops them on overflow:
/// ```c
/// // C pattern (from log.c)
/// if (entries && entries->next == NULL) {
///     // Queue full, drop message
///     entries->next = entry; 
/// }
/// ```
///
/// Rust makes queue overflow explicit:
/// ```rust,ignore
/// log_queue.push(entry)
///     .map_err(|_| LogError::QueueOverflow { 
///         queue_size: MAX_LOGS 
///     })?;
/// ```
#[derive(Debug, Error)]
pub enum LogError {
    /// Failed to initialize logging subsystem
    #[error("Failed to initialize logging: {message}")]
    InitializationFailed {
        /// Description of initialization failure
        message: String,
        /// Underlying error
        #[source]
        source: Option<io::Error>,
    },

    /// Failed to write log message
    #[error("Failed to write log message")]
    WriteFailed {
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Failed to reopen log file (rotation)
    #[error("Failed to reopen log file: {path}")]
    ReopenFailed {
        /// Log file path
        path: String,
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Log message queue overflow
    #[error("Log queue overflow: {dropped} messages dropped (queue size: {queue_size})")]
    QueueOverflow {
        /// Number of messages dropped
        dropped: usize,
        /// Maximum queue size
        queue_size: usize,
    },

    /// Invalid logging configuration
    #[error("Invalid logging configuration: {message}")]
    InvalidConfiguration {
        /// Description of configuration error
        message: String,
    },
}

/// DNSSEC validation errors
///
/// Covers DNSSEC signature validation, trust chain verification,
/// cryptographic operations, and timestamp handling. These replace
/// C's error handling in dnssec.c and dnssec-crypto.c.
///
/// # DNSSEC Validation Errors
///
/// C returns validation status codes:
/// ```c
/// // C pattern (from dnssec.c)
/// if (validate_rrset(...) == STAT_INSECURE)
///     return STAT_INSECURE;
/// ```
///
/// Rust uses detailed error types:
/// ```rust,ignore
/// validate_rrset(rrset)
///     .map_err(|_| DnssecError::InvalidSignature {
///         signer: signer_name.into(),
///         algorithm: algo,
///     })?;
/// ```
#[derive(Debug, Error)]
pub enum DnssecError {
    /// Cryptographic operation failed
    #[error("DNSSEC crypto error: {message}")]
    CryptoError {
        /// Description of crypto failure
        message: String,
    },

    /// Timestamp validation failed
    #[error("DNSSEC timestamp invalid: signature {status} (inception: {inception}, expiration: {expiration})")]
    InvalidTimestamp {
        /// Status (expired, not yet valid)
        status: String,
        /// Signature inception time
        inception: u32,
        /// Signature expiration time
        expiration: u32,
    },

    /// Required DNSKEY record missing
    #[error("DNSSEC: Missing DNSKEY for {zone}")]
    MissingDnskey {
        /// Zone name
        zone: String,
    },

    /// Required DS record missing
    #[error("DNSSEC: Missing DS record for {zone}")]
    MissingDs {
        /// Zone name
        zone: String,
    },

    /// Signature validation failed
    #[error("DNSSEC: Invalid signature from {signer} using algorithm {algorithm}")]
    InvalidSignature {
        /// Signer name
        signer: String,
        /// Cryptographic algorithm ID
        algorithm: u8,
    },

    /// NSEC proof of non-existence failed
    #[error("DNSSEC: NSEC proof failed for {name}")]
    NsecProofFailed {
        /// Query name
        name: String,
    },

    /// NSEC3 proof of non-existence failed
    #[error("DNSSEC: NSEC3 proof failed for {name}")]
    Nsec3ProofFailed {
        /// Query name
        name: String,
    },

    /// Trust chain broken
    #[error("DNSSEC: Chain of trust broken at {zone}")]
    ChainOfTrustBroken {
        /// Zone where trust fails
        zone: String,
    },

    /// Base32 encoding error (NSEC3)
    #[error("DNSSEC: Invalid base32 encoding in NSEC3")]
    InvalidBase32Encoding,

    /// Malformed DNSSEC record
    #[error("DNSSEC: Malformed {record_type} record")]
    MalformedRecord {
        /// Record type (RRSIG, DNSKEY, DS, etc.)
        record_type: String,
    },

    /// Timestamp file I/O error
    #[error("DNSSEC: Timestamp file error")]
    TimestampFileError {
        /// Underlying OS error
        #[source]
        source: io::Error,
    },

    /// Query timeout during validation
    #[error("DNSSEC: Query timeout for {name}")]
    QueryTimeout {
        /// Query name
        name: String,
    },
}

/// Authoritative DNS server errors
///
/// Covers errors in authoritative zone serving, subnet matching,
/// and query processing. These replace C's error handling in auth.c.
///
/// # Authoritative DNS Errors
///
/// C uses implicit error handling:
/// ```c
/// // C pattern (from auth.c)
/// if (!in_zone(zone, name, NULL))
///     return 0; // Not authoritative
/// ```
///
/// Rust uses explicit error types:
/// ```rust,ignore
/// if !zone.contains(&query_name) {
///     return Err(AuthError::NotInZone {
///         zone: zone.name.clone(),
///         query: query_name.clone(),
///     });
/// }
/// ```
#[derive(Debug, Error)]
pub enum AuthError {
    /// Query name not in authoritative zone
    #[error("Query {query} not in authoritative zone {zone}")]
    NotInZone {
        /// Authoritative zone name
        zone: String,
        /// Query name
        query: String,
    },

    /// No authority for client subnet
    #[error("No authority for subnet {subnet}")]
    NoAuthorityForSubnet {
        /// Client subnet
        subnet: String,
    },

    /// Malformed query for authoritative zone
    #[error("Malformed authoritative query: {message}")]
    MalformedQuery {
        /// Description of query error
        message: String,
    },

    /// Packet truncated, TCP retry required
    #[error("Authoritative response truncated")]
    PacketTruncated,

    /// Internal error in authoritative server
    #[error("Internal authoritative server error: {message}")]
    InternalError {
        /// Description of internal error
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let dns_err = DnsError::ProtocolError {
            message: "Invalid header".into(),
        };
        assert!(dns_err.to_string().contains("Invalid header"));

        let dhcp_err = DhcpError::NoAvailableAddress {
            client_id: "00:11:22:33:44:55".into(),
        };
        assert!(dhcp_err.to_string().contains("00:11:22:33:44:55"));
    }

    #[test]
    fn test_error_conversion() {
        let dns_err = DnsError::Timeout { timeout_ms: 5000 };
        let dnsmasq_err: DnsmasqError = dns_err.into();
        assert!(matches!(dnsmasq_err, DnsmasqError::Dns(_)));
    }

    #[test]
    fn test_error_source_chaining() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let config_err = ConfigError::PermissionDenied {
            path: "/etc/dnsmasq.conf".into(),
            source: io_err,
        };
        
        // Verify error chain exists
        assert!(config_err.source().is_some());
        assert!(config_err.to_string().contains("/etc/dnsmasq.conf"));
    }

    #[test]
    fn test_network_error_context() {
        let net_err = NetworkError::BindFailed {
            address: "0.0.0.0:53".into(),
            source: io::Error::new(io::ErrorKind::AddrInUse, "address in use"),
        };
        
        let err_string = net_err.to_string();
        assert!(err_string.contains("0.0.0.0:53"));
        assert!(err_string.contains("bind"));
    }

    #[test]
    fn test_system_error_privilege_drop() {
        let sys_err = SystemError::PrivilegeDropFailed {
            target_uid: 1000,
            target_gid: 1000,
            source: io::Error::new(io::ErrorKind::PermissionDenied, "operation not permitted"),
        };
        
        let err_string = sys_err.to_string();
        assert!(err_string.contains("1000"));
        assert!(err_string.contains("privileges"));
    }

    #[test]
    fn test_dnssec_error_details() {
        let dnssec_err = DnssecError::InvalidSignature {
            signer: "example.com".into(),
            algorithm: 8, // RSA/SHA-256
        };
        
        let err_string = dnssec_err.to_string();
        assert!(err_string.contains("example.com"));
        assert!(err_string.contains("8"));
    }

    #[test]
    fn test_result_type_alias() {
        fn test_function() -> DnsmasqResult<i32> {
            Ok(42)
        }
        
        assert_eq!(test_function().unwrap(), 42);
    }
}

