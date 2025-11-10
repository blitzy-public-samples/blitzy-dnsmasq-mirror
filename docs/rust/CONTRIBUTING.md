# Contributing to dnsmasq-rs

Welcome to the dnsmasq Rust implementation project! This document provides comprehensive guidelines for contributing to the memory-safe Rust port of dnsmasq. We appreciate your interest in helping us achieve a drop-in replacement for the C implementation with zero memory-safety vulnerabilities.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Environment Setup](#development-environment-setup)
- [Code Style Standards](#code-style-standards)
- [Linting Rules](#linting-rules)
- [Documentation Standards](#documentation-standards)
- [Error Handling Patterns](#error-handling-patterns)
- [Memory Safety Requirements](#memory-safety-requirements)
- [Testing Requirements](#testing-requirements)
- [Commit Message Conventions](#commit-message-conventions)
- [Pull Request Process](#pull-request-process)
- [Async Programming Patterns](#async-programming-patterns)
- [Platform-Specific Code](#platform-specific-code)
- [Review Checklist](#review-checklist)

## Code of Conduct

All contributors must follow the Rust community standards and code of conduct:

- **Be respectful and inclusive**: Treat all contributors with respect regardless of their experience level, background, or identity
- **Be constructive**: Provide helpful feedback and focus on improving the codebase
- **Be collaborative**: Work together to find the best solutions
- **Follow Rust community guidelines**: Adhere to the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct)

Violations of the code of conduct will not be tolerated and may result in removal from the project.

## Development Environment Setup

### Required Tools

The dnsmasq-rs project requires the following tools and versions:

- **Rust 1.91.0** (stable channel, enforced via rust-toolchain.toml)
- **Cargo** (included with Rust for build management)
- **rustfmt** (for automatic code formatting)
- **clippy** (for linting and code quality checks)
- **cargo-tarpaulin** (for code coverage measurement, target: >80%)
- **cargo-audit** (for security vulnerability scanning)

### Installation

#### Install Rust Toolchain

The project uses rust-toolchain.toml to automatically install the correct Rust version:

```bash
# Install rustup (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# The rust-toolchain.toml file will automatically install Rust 1.91.0
# when you run any cargo command in the project directory
```

#### Install Additional Development Tools

```bash
# Install code coverage tool
cargo install cargo-tarpaulin

# Install security audit tool
cargo install cargo-audit

# Install test utilities (optional)
cargo install cargo-nextest  # Faster test runner
```

#### Verify Installation

```bash
# Check Rust version (should be 1.91.0)
rustc --version

# Check formatting tool
cargo fmt --version

# Check linting tool
cargo clippy --version

# Check coverage tool
cargo tarpaulin --version
```

### Building the Project

```bash
# Clone the repository
git clone https://github.com/your-org/dnsmasq-rs.git
cd dnsmasq-rs

# Build with all features
cargo build --all-features

# Build optimized release version
cargo build --release --all-features

# Build with specific features
cargo build --features "dhcp,dns,dnssec"
```

### Running Tests

```bash
# Run all tests
cargo test --all-features

# Run tests with output
cargo test --all-features -- --nocapture

# Run specific test
cargo test test_dns_cache

# Run integration tests only
cargo test --test '*'

# Run with coverage
cargo tarpaulin --out Html --output-dir coverage/
```

## Code Style Standards

### Formatting

All code must be formatted using **rustfmt** with the project's configuration:

- **Tool**: rustfmt (automatic formatting)
- **Configuration**: `rustfmt.toml` in project root
- **Line length**: 100 characters maximum
- **Indentation**: 4 spaces (no tabs)
- **Trailing commas**: Required in multi-line expressions
- **Imports**: Grouped by std/external/internal, sorted alphabetically within each group

#### Running rustfmt

```bash
# Format all code in the project
cargo fmt --all

# Check formatting without modifying files
cargo fmt --all -- --check

# Format a specific file
rustfmt src/dns/cache.rs
```

**Important**: Always run `cargo fmt --all` before committing code. CI will reject PRs with formatting violations.

### Naming Conventions

Follow Rust naming conventions strictly:

#### Types (PascalCase)

```rust
// Structs, enums, traits
pub struct DnsCache { }
pub enum DhcpMessageType { }
pub trait NetworkInterface { }
```

#### Functions and Methods (snake_case)

```rust
// Functions, methods, variables
pub fn parse_dns_query(data: &[u8]) -> Result<DnsQuery> { }
pub fn allocate_lease(&mut self) -> Result<DhcpLease> { }
fn validate_domain_name(name: &str) -> bool { }
```

#### Constants (SCREAMING_SNAKE_CASE)

```rust
// Constants and static values
pub const MAX_PACKET_SIZE: usize = 4096;
pub const DEFAULT_TTL: u32 = 3600;
const DNS_PORT: u16 = 53;
```

#### Modules (snake_case)

```rust
// Module names
mod dns_cache;
mod dhcp_server;
mod network_interface;
```

#### Lifetime Parameters (lowercase single letter)

```rust
// Prefer descriptive names when multiple lifetimes exist
fn process_query<'a, 'b>(query: &'a str, cache: &'b Cache) -> &'b Entry
```

### Import Organization

Organize imports into three groups, separated by blank lines:

```rust
// 1. Standard library imports
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

// 2. External crate imports
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// 3. Internal crate imports
use crate::config::ConfigOptions;
use crate::dns::cache::DnsCache;
use crate::types::daemon_state::DaemonState;
```

## Linting Rules

### Clippy Configuration

All code must pass clippy checks with the following configuration:

- **Level**: Deny warnings in CI (per Section 0.7.9 of the technical specification)
- **Configuration**: `clippy.toml` in project root
- **Required checks**: all, correctness, suspicious, complexity, perf
- **Custom lint levels**: Defined in clippy.toml

#### Running Clippy

```bash
# Run clippy with all features
cargo clippy --all-features -- -D warnings

# Run clippy on specific package
cargo clippy -p dnsmasq-rs -- -D warnings

# Run clippy with pedantic lints (for extra checks)
cargo clippy --all-features -- -D warnings -W clippy::pedantic
```

### Critical Lints (Denied)

The following lints are explicitly denied and will cause CI failures:

#### Memory Safety Lints

```rust
// ❌ DENIED: Prevent memory leaks
#![deny(clippy::mem_forget)]

// ❌ DENIED: Require documentation for unsafe code
#![deny(clippy::missing_safety_doc)]

// ❌ DENIED: All unsafe blocks must be documented
#![deny(clippy::undocumented_unsafe_blocks)]

// ❌ DENIED: Prevent reference-counted cycles
#![deny(clippy::rc_mutex)]
```

#### Correctness Lints

```rust
// ❌ DENIED: Prevent integer overflow in protocol parsing
#![deny(clippy::integer_arithmetic)]

// ❌ DENIED: Prevent panics on malformed packets
#![deny(clippy::indexing_slicing)]

// ❌ DENIED: Prevent lossy conversions
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]

// ❌ DENIED: Ensure error handling
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
```

#### Code Quality Lints

```rust
// ❌ DENIED: Prevent inefficient patterns
#![deny(clippy::inefficient_to_string)]
#![deny(clippy::needless_pass_by_value)]

// ❌ DENIED: Ensure documentation
#![deny(clippy::missing_docs_in_private_items)]  // For critical modules only
```

### Allowed Exceptions

Some lints may be allowed in specific contexts with justification:

```rust
// ✅ ALLOWED: In tests where panics are acceptable
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    // Test code can use unwrap()
}

// ✅ ALLOWED: With explicit justification
#[allow(clippy::too_many_arguments)]  // Protocol parsers may need many parameters
fn parse_dhcp_options(/* ... many parameters ... */) -> Result<Options> {
    // Implementation
}
```

## Documentation Standards

Comprehensive documentation is required for all public APIs and modules, following Section 0.7.8 of the technical specification.

### Module-Level Documentation

Every module (`mod.rs` or single-file module) must have `//!` documentation explaining its purpose and relationship to the C implementation:

```rust
//! DNS caching subsystem implementing LRU eviction policy.
//!
//! This module provides a thread-safe DNS cache using HashMap with
//! Arc<RwLock<T>> for concurrent access. It replaces the C implementation's
//! manual freelist cache management from src/cache.c.
//!
//! # Key Changes from C Implementation
//!
//! - **HashMap replaces power-of-two hash table**: Provides O(1) lookups with
//!   better collision handling than C's fixed-size hash table
//! - **Automatic memory management via RAII**: Eliminates manual freelist
//!   management and prevents memory leaks
//! - **Type-safe cache entries**: Eliminates unsafe pointer casting required
//!   in C implementation
//! - **Built-in bounds checking**: Prevents buffer overflows present in C's
//!   fixed-size arrays
//!
//! # Architecture
//!
//! The cache is implemented as a two-level structure:
//! - Primary HashMap for O(1) domain name lookups
//! - LRU doubly-linked list for efficient eviction
//!
//! # Example
//!
//! ```rust
//! use dnsmasq_rs::dns::cache::DnsCache;
//!
//! let mut cache = DnsCache::new(1000);  // 1000 entry capacity
//! cache.insert("example.com", record, 300)?;
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
```

### Function Documentation

All public functions and methods must have `///` doc comments with the following sections:

```rust
/// Inserts a DNS record into the cache with TTL-based expiration.
///
/// This function adds a new DNS record to the cache, or updates an existing
/// entry if the domain name already exists. Records are automatically evicted
/// when their TTL expires or when the cache reaches capacity.
///
/// # Arguments
///
/// * `query` - Domain name to cache (e.g., "example.com")
/// * `record` - DNS record data to store
/// * `ttl` - Time to live in seconds (0 = no caching)
///
/// # Returns
///
/// * `Ok(())` - Record successfully cached
/// * `Err(CacheError::Full)` - Cache at capacity and no entries can be evicted
/// * `Err(CacheError::InvalidQuery)` - Query name is malformed
///
/// # Example
///
/// ```rust
/// use std::net::Ipv4Addr;
/// use dnsmasq_rs::dns::cache::{DnsCache, DnsRecord};
///
/// let mut cache = DnsCache::new(1000);
/// let record = DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1));
/// cache.insert("example.com", record, 300)?;
/// ```
///
/// # Panics
///
/// This function does not panic under normal conditions.
///
/// # Safety
///
/// This function is completely safe and uses no unsafe code.
pub fn insert(&mut self, query: &str, record: DnsRecord, ttl: u32) -> Result<(), CacheError> {
    // Implementation
}
```

### Type Documentation

All public types must have comprehensive `///` doc comments:

```rust
/// DNS cache entry with expiration timestamp and metadata.
///
/// This structure represents a single cached DNS record. It replaces
/// the C implementation's `struct crec` from src/dnsmasq.h lines 450-480,
/// providing type safety and automatic memory management.
///
/// # Fields
///
/// * `record` - The cached DNS record data (A, AAAA, CNAME, etc.)
/// * `expires_at` - Unix timestamp when this entry expires
/// * `insert_time` - Unix timestamp when entry was added (for statistics)
/// * `access_count` - Number of times this entry has been accessed
///
/// # Memory Layout
///
/// Unlike the C implementation which uses unions for different record types,
/// this structure uses Rust enums for type-safe storage without wasting memory.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheEntry {
    /// Cached DNS record data
    pub record: DnsRecord,
    
    /// Expiration time (Unix timestamp in seconds)
    pub expires_at: u64,
    
    /// Insertion time for statistics tracking
    pub insert_time: u64,
    
    /// Access counter for LRU eviction policy
    pub access_count: u64,
}
```

### Error Type Documentation

Document all error variants comprehensively:

```rust
/// Errors that can occur during DNS operations.
///
/// This enum represents all possible error conditions in the DNS subsystem,
/// replacing C's errno-based error handling with type-safe Result types.
#[derive(Error, Debug)]
pub enum DnsError {
    /// Invalid DNS query name (empty, too long, or malformed)
    #[error("invalid query name: {0}")]
    InvalidQuery(String),
    
    /// Cache is full and no entries can be evicted
    #[error("cache full, cannot insert record")]
    CacheFull,
    
    /// DNS packet parsing failed
    #[error("failed to parse DNS packet: {0}")]
    ParseError(String),
    
    /// Network I/O error occurred
    #[error("network I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    /// Query timeout waiting for upstream server
    #[error("query timeout after {0} seconds")]
    Timeout(u64),
}
```

### Migration Documentation

Document significant changes from the C implementation:

```rust
/// Replaces C's manual buffer management with Rust's Vec<u8>.
///
/// # C Implementation Context
///
/// The C version (src/rfc1035.c:extract_name) used fixed-size buffers with
/// manual bounds checking:
/// ```c
/// char buffer[MAXDNAME];
/// if (len > MAXDNAME) return 0;  // Error handling
/// memcpy(buffer, src, len);
/// ```
///
/// This approach had several vulnerabilities:
/// - Buffer overflow if bounds check was missed
/// - No automatic cleanup on early return
/// - Manual memory management complexity
///
/// # Rust Implementation
///
/// The Rust version eliminates these vulnerabilities:
/// - Vec<u8> automatically grows as needed (within system limits)
/// - Bounds checking is automatic and compile-time verified
/// - RAII ensures cleanup even on early return or panic
/// - Type system prevents use-after-free
///
/// # Example
///
/// ```rust
/// // Safe automatic growth, no manual bounds checking needed
/// let mut buffer = Vec::new();
/// buffer.extend_from_slice(&data);  // Can't overflow
/// ```
pub fn extract_name(packet: &[u8], offset: usize) -> Result<String, DnsError> {
    // Implementation
}
```

## Error Handling Patterns

The project uses Rust's type-safe error handling exclusively. Never use panic!, unwrap(), or expect() in production code.

### Defining Error Types

Use the `thiserror` crate for error definitions:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("invalid query name: {0}")]
    InvalidQuery(String),
    
    #[error("cache full, cannot insert record")]
    CacheFull,
    
    #[error("malformed DNS packet at offset {offset}: {reason}")]
    MalformedPacket {
        offset: usize,
        reason: String,
    },
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("timeout after {0}s")]
    Timeout(u64),
}

/// Result type alias for DNS operations
pub type Result<T> = std::result::Result<T, DnsError>;
```

### Propagating Errors with ?

Always use the `?` operator for error propagation:

```rust
fn process_query(data: &[u8]) -> Result<DnsResponse> {
    // Propagate errors automatically
    let query = parse_query(data)?;
    let cached = lookup_cache(&query)?;
    let response = build_response(cached)?;
    
    Ok(response)
}
```

### Error Context

Add context to errors using helper methods:

```rust
use anyhow::Context;

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let contents = std::fs::read_to_string(path)
        .context(format!("failed to read config file: {}", path.display()))?;
    
    let config = toml::from_str(&contents)
        .context("failed to parse TOML configuration")?;
    
    Ok(config)
}
```

### Handling Multiple Error Types

Convert between error types explicitly:

```rust
fn query_upstream(server: &str) -> Result<DnsResponse> {
    // Convert std::io::Error to DnsError automatically
    let socket = UdpSocket::bind("0.0.0.0:0")?;  // Uses #[from] conversion
    
    // Convert timeout error manually
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        send_query(&socket, server)
    )
    .await
    .map_err(|_| DnsError::Timeout(5))?;
    
    response
}
```

### Never Use Panics in Production Code

```rust
// ❌ BAD: Will crash the server
fn get_cache_entry(key: &str) -> DnsRecord {
    cache.get(key).unwrap()  // Panics if key not found
}

// ✅ GOOD: Returns Result for caller to handle
fn get_cache_entry(key: &str) -> Result<DnsRecord> {
    cache.get(key)
        .ok_or_else(|| DnsError::NotFound(key.to_string()))
}
```

## Memory Safety Requirements

Per Section 0.7.2 of the technical specification, the project enforces strict memory safety requirements.

### Zero Unsafe in Core Logic

**Rule**: No `unsafe` blocks are permitted in DNS/DHCP/TFTP protocol code.

**Exception**: Platform-specific FFI code only (netlink, BPF, system calls via nix crate).

#### Allowed Unsafe (Platform FFI)

```rust
// src/platform/linux/netlink.rs
use libc::{c_int, sockaddr_nl};

pub fn create_netlink_socket() -> Result<RawFd> {
    // SAFETY: This is safe because:
    // 1. AF_NETLINK and SOCK_RAW are valid constants
    // 2. Protocol number is within valid range
    // 3. File descriptor is checked for validity (-1 indicates error)
    // 4. No memory is accessed through raw pointers
    let fd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)
    };
    
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    
    Ok(fd)
}
```

#### Prohibited Unsafe (Protocol Code)

```rust
// ❌ NEVER DO THIS: Unsafe in protocol parsing
fn parse_dns_name(packet: &[u8], offset: usize) -> String {
    unsafe {
        // This is FORBIDDEN - use safe Rust instead
        let ptr = packet.as_ptr().add(offset);
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(ptr, 255))
    }
}

// ✅ CORRECT: Safe Rust with proper bounds checking
fn parse_dns_name(packet: &[u8], offset: usize) -> Result<String> {
    let data = packet.get(offset..)
        .ok_or(DnsError::InvalidOffset(offset))?;
    
    let name = std::str::from_utf8(data)
        .map_err(|e| DnsError::InvalidUtf8(e))?;
    
    Ok(name.to_string())
}
```

### Documentation for Unsafe Code

Every unsafe block must have a comprehensive safety comment:

```rust
// SAFETY: This is safe because:
// 1. Buffer size has been verified to be >= required length on line XX
// 2. Pointer `optval` is valid for the lifetime of `buffer`
// 3. No concurrent access to this buffer exists (checked by borrow checker)
// 4. `setsockopt` is documented to only read `optlen` bytes from `optval`
// 5. File descriptor `fd` is valid (checked on line XX)
unsafe {
    libc::setsockopt(fd, level, optname, optval as *const _, optlen)
}
```

### Ownership Patterns

Use appropriate ownership patterns for different scenarios:

#### Shared Immutable Data

```rust
use std::sync::Arc;

// Multiple readers, no writers
let config: Arc<Config> = Arc::new(load_config()?);
let dns_config = Arc::clone(&config);
let dhcp_config = Arc::clone(&config);
```

#### Shared Mutable Data (Multi-threaded)

```rust
use std::sync::Arc;
use tokio::sync::RwLock;

// Multiple readers, occasional writers
let cache: Arc<RwLock<DnsCache>> = Arc::new(RwLock::new(DnsCache::new()));

// Read access
let cached_value = cache.read().await.lookup("example.com");

// Write access
cache.write().await.insert("example.com", record, 300)?;
```

#### Shared Mutable Data (Single-threaded)

```rust
use std::rc::Rc;
use std::cell::RefCell;

// Single-threaded code only
let state: Rc<RefCell<State>> = Rc::new(RefCell::new(State::new()));
state.borrow_mut().update();
```

#### Prefer Borrowing

```rust
// ✅ GOOD: Borrow instead of cloning
fn process_config(config: &Config) -> Result<()> {
    // Use config without taking ownership
}

// ❌ AVOID: Unnecessary cloning
fn process_config(config: Config) -> Result<()> {
    // Takes ownership, forces caller to clone
}
```

### Preventing Common Memory Bugs

The Rust compiler prevents these bugs at compile time:

```rust
// ✅ Buffer overflow prevented by bounds checking
let data = &packet[0..100];  // Panics if packet.len() < 100
let data = packet.get(0..100).ok_or(Error::InvalidPacket)?;  // Safe version

// ✅ Use-after-free prevented by borrow checker
let entry = cache.get("example.com");
cache.clear();  // Compile error: can't mutate while borrowed

// ✅ Double-free prevented by ownership
let data = vec![1, 2, 3];
drop(data);
// data can't be used here - compile error

// ✅ Null pointer dereference prevented by Option
let entry: Option<CacheEntry> = cache.get(key);
match entry {
    Some(e) => process(e),
    None => return Err(Error::NotFound),
}
```

## Testing Requirements

Per Section 0.7.4 of the technical specification, comprehensive testing is required with >80% code coverage.

### Unit Tests (>80% Coverage Target)

Every module must have inline unit tests using `#[cfg(test)]`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cache_insert_and_lookup() {
        let mut cache = DnsCache::new(100);
        let record = DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1));
        
        // Insert record
        cache.insert("example.com", record.clone(), 300).unwrap();
        
        // Verify lookup
        let result = cache.lookup("example.com");
        assert_eq!(result, Some(record));
    }
    
    #[test]
    fn test_cache_eviction_on_full() {
        let mut cache = DnsCache::new(2);  // Small cache
        
        // Fill cache
        cache.insert("example1.com", DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1)), 300).unwrap();
        cache.insert("example2.com", DnsRecord::A(Ipv4Addr::new(192, 0, 2, 2)), 300).unwrap();
        
        // Insert third record, should evict LRU
        cache.insert("example3.com", DnsRecord::A(Ipv4Addr::new(192, 0, 2, 3)), 300).unwrap();
        
        // Verify eviction
        assert!(cache.lookup("example1.com").is_none());
        assert!(cache.lookup("example3.com").is_some());
    }
    
    #[test]
    fn test_ttl_expiration() {
        let mut cache = DnsCache::new(100);
        let record = DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1));
        
        // Insert with 0 TTL (already expired)
        cache.insert("example.com", record, 0).unwrap();
        
        // Should not be found (expired)
        assert!(cache.lookup("example.com").is_none());
    }
}
```

### Integration Tests

Place integration tests in the `tests/` directory:

```rust
// tests/integration/dns_tests.rs
use dnsmasq_rs::dns::server::DnsServer;
use dnsmasq_rs::config::Config;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_dns_query_response() {
    // Start test DNS server
    let config = Config::default();
    let server = DnsServer::new(config).await.unwrap();
    let addr = server.local_addr();
    
    // Spawn server task
    tokio::spawn(async move {
        server.run().await.unwrap();
    });
    
    // Send DNS query
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let query = build_dns_query("example.com");
    socket.send_to(&query, addr).await.unwrap();
    
    // Receive response
    let mut buf = [0u8; 4096];
    let (len, _) = socket.recv_from(&mut buf).await.unwrap();
    let response = parse_dns_response(&buf[..len]).unwrap();
    
    // Verify response
    assert_eq!(response.status_code, StatusCode::NoError);
    assert!(!response.answers.is_empty());
}

#[tokio::test]
async fn test_dns_cache_hit() {
    // Test that subsequent queries are served from cache
    let mut server = DnsServer::new(Config::default()).await.unwrap();
    
    // First query (cache miss)
    let response1 = server.query("example.com").await.unwrap();
    assert_eq!(server.cache_stats().misses, 1);
    
    // Second query (cache hit)
    let response2 = server.query("example.com").await.unwrap();
    assert_eq!(server.cache_stats().hits, 1);
    
    // Responses should be identical
    assert_eq!(response1, response2);
}
```

### Property-Based Tests

Use `proptest` for protocol correctness validation:

```rust
// tests/property_tests.rs
use proptest::prelude::*;
use dnsmasq_rs::dns::protocol::{DnsQuery, serialize_query, parse_query};

proptest! {
    /// Verify that parse(serialize(x)) == x for all DNS queries
    #[test]
    fn parse_serialize_roundtrip(query in any::<DnsQuery>()) {
        let serialized = serialize_query(&query).unwrap();
        let parsed = parse_query(&serialized).unwrap();
        prop_assert_eq!(query, parsed);
    }
    
    /// Verify that parser never panics on any input
    #[test]
    fn parse_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        // Should return Ok or Err, never panic
        let _ = parse_query(&data);
    }
    
    /// Verify that domain names are correctly validated
    #[test]
    fn domain_validation(name in "[a-z0-9-]{1,63}(\\.[a-z0-9-]{1,63}){0,10}") {
        let result = validate_domain_name(&name);
        prop_assert!(result.is_ok());
    }
}

// Custom strategy for generating valid DNS queries
impl Arbitrary for DnsQuery {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            "[a-z0-9-]{1,63}(\\.[a-z0-9-]{1,63}){0,10}",  // Domain name
            any::<u16>(),  // Transaction ID
            prop::bool::ANY,  // Recursion desired
        )
            .prop_map(|(name, id, rd)| DnsQuery {
                name,
                transaction_id: id,
                recursion_desired: rd,
            })
            .boxed()
    }
}
```

### Mock Testing

Use `mockall` for testing with external dependencies:

```rust
use mockall::predicate::*;
use mockall::mock;

// Define mock for network interface
mock! {
    pub NetworkInterface {}
    
    impl NetworkInterface {
        fn send(&self, data: &[u8]) -> Result<usize>;
        fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
    }
}

#[test]
fn test_dns_forwarding_with_mock() {
    let mut mock_net = MockNetworkInterface::new();
    
    // Set expectations
    mock_net.expect_send()
        .with(eq(b"query_data"))
        .times(1)
        .returning(|_| Ok(10));
    
    mock_net.expect_recv()
        .times(1)
        .returning(|buf| {
            buf[..8].copy_from_slice(b"response");
            Ok(8)
        });
    
    // Test with mock
    let forwarder = DnsForwarder::new(mock_net);
    let response = forwarder.forward(b"query_data").unwrap();
    assert_eq!(response, b"response");
}
```

### Coverage Measurement

Measure code coverage using cargo-tarpaulin:

```bash
# Generate HTML coverage report
cargo tarpaulin --out Html --output-dir coverage/ --all-features

# Generate coverage for specific package
cargo tarpaulin -p dnsmasq-rs --out Html

# Enforce minimum coverage (80%)
cargo tarpaulin --out Html --fail-under 80

# Generate Codecov-compatible output
cargo tarpaulin --out Xml
```

### Benchmark Tests

Use `criterion` for performance benchmarking:

```rust
// benches/dns_cache.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dnsmasq_rs::dns::cache::DnsCache;

fn benchmark_cache_insert(c: &mut Criterion) {
    c.bench_function("cache_insert", |b| {
        let mut cache = DnsCache::new(10000);
        let record = DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1));
        let mut i = 0;
        
        b.iter(|| {
            let key = format!("example{}.com", i);
            cache.insert(black_box(&key), record.clone(), 300).unwrap();
            i += 1;
        });
    });
}

fn benchmark_cache_lookup(c: &mut Criterion) {
    let mut cache = DnsCache::new(10000);
    
    // Pre-populate cache
    for i in 0..1000 {
        let key = format!("example{}.com", i);
        let record = DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1));
        cache.insert(&key, record, 300).unwrap();
    }
    
    c.bench_function("cache_lookup", |b| {
        b.iter(|| {
            let key = format!("example{}.com", black_box(500));
            cache.lookup(black_box(&key))
        });
    });
}

criterion_group!(benches, benchmark_cache_insert, benchmark_cache_lookup);
criterion_main!(benches);
```

## Commit Message Conventions

Follow conventional commit format for clear history and automated changelog generation.

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature implementation
- **fix**: Bug fix
- **docs**: Documentation changes only
- **style**: Formatting changes (rustfmt, whitespace)
- **refactor**: Code refactoring without behavior change
- **perf**: Performance improvements
- **test**: Adding or modifying tests
- **chore**: Build system, tooling, dependencies
- **ci**: CI/CD pipeline changes

### Scope

Specify the module or component affected:

- `dns`: DNS subsystem changes
- `dhcp`: DHCP subsystem changes
- `tftp`: TFTP server changes
- `config`: Configuration parsing
- `cache`: Caching implementation
- `network`: Network layer
- `platform`: Platform-specific code
- `deps`: Dependency updates

### Subject

- Use imperative mood ("add" not "added" or "adds")
- Don't capitalize first letter
- No period at the end
- Maximum 50 characters
- Be specific and descriptive

### Body

- Wrap at 72 characters
- Explain what and why, not how
- Reference related C source files when applicable
- Include breaking changes

### Footer

- Reference issues: `Resolves: #123`, `Closes: #456`
- Note breaking changes: `BREAKING CHANGE: description`
- Reference related commits

### Examples

#### Feature Addition

```
feat(dns): implement DNS cache with LRU eviction

Replaces C's manual freelist cache (src/cache.c) with Rust HashMap
using RAII for automatic memory management. This provides:

- O(1) lookups instead of linear probing
- Compile-time memory safety eliminating use-after-free bugs
- Automatic cleanup on cache entry expiration
- Thread-safe access via Arc<RwLock<T>>

The implementation maintains identical cache semantics to the C version
including TTL handling, negative caching, and DNSSEC-aware storage.

Resolves: #123
Refs: src/cache.c (C implementation)
```

#### Bug Fix

```
fix(dhcp): correct lease expiration calculation

Fixed integer overflow in lease expiration time calculation when
lease duration exceeds 2^31 seconds. The C implementation (src/lease.c)
used signed 32-bit integers, which caused wrap-around for long leases.

The Rust implementation now uses u64 for all time calculations,
eliminating overflow possibility while maintaining compatibility
with existing lease file format.

Closes: #456
```

#### Documentation

```
docs(contributing): add property-based testing examples

Added comprehensive examples for using proptest to validate
protocol implementations. Includes:

- DNS query/response round-trip properties
- DHCP packet serialization properties
- Custom Arbitrary implementations for protocol types
```

#### Refactoring

```
refactor(network): extract socket handling into trait

Refactored platform-specific socket handling into a common
NetworkInterface trait, reducing code duplication across
Linux netlink, BSD BPF, and generic implementations.

No behavioral changes, all tests pass.
```

## Pull Request Process

Follow this process for all contributions:

### 1. Fork and Branch

```bash
# Fork repository on GitHub
# Clone your fork
git clone https://github.com/your-username/dnsmasq-rs.git
cd dnsmasq-rs

# Create feature branch
git checkout -b feat/dns-cache-implementation
```

### 2. Make Changes

- Implement your feature or fix following all coding standards
- Write comprehensive tests (maintain >80% coverage)
- Document all public APIs with rustdoc comments
- Add examples where appropriate

### 3. Format and Lint

```bash
# Format all code
cargo fmt --all

# Run clippy with strict checks
cargo clippy --all-features -- -D warnings

# Verify no warnings
cargo build --all-features 2>&1 | grep -i warning
```

### 4. Run Tests

```bash
# Run all tests
cargo test --all-features

# Run integration tests
cargo test --test '*'

# Check coverage
cargo tarpaulin --out Html --fail-under 80

# Run security audit
cargo audit
```

### 5. Commit Changes

```bash
# Stage changes
git add src/dns/cache.rs tests/dns/cache_tests.rs

# Commit with conventional format
git commit -m "feat(dns): implement LRU cache with TTL support"
```

### 6. Push and Create PR

```bash
# Push to your fork
git push origin feat/dns-cache-implementation

# Create pull request on GitHub with:
# - Clear title following conventional commit format
# - Comprehensive description of changes
# - Reference to related issues
# - Screenshots/examples if applicable
```

### 7. Address Review Feedback

- Respond to all reviewer comments
- Make requested changes in new commits (don't force push)
- Re-run tests and linting after changes
- Mark conversations as resolved when addressed

### 8. Merge

After approval:
- Squash commits if requested
- Ensure CI passes
- Maintainer will merge

## Async Programming Patterns

The project uses Tokio for async I/O. Follow these patterns for consistency.

### Tokio Best Practices

#### Server Event Loop

```rust
use tokio::net::UdpSocket;
use tokio::select;
use tokio::signal;

/// DNS server main event loop
pub async fn dns_server_loop(socket: UdpSocket) -> Result<()> {
    let mut buf = [0u8; 4096];
    let mut shutdown = signal::ctrl_c();
    
    loop {
        select! {
            // Handle incoming DNS queries
            result = socket.recv_from(&mut buf) => {
                let (len, addr) = result?;
                let query = &buf[..len];
                
                // Spawn task to handle query asynchronously
                tokio::spawn(async move {
                    if let Err(e) = process_query(query, addr).await {
                        tracing::error!("query processing failed: {}", e);
                    }
                });
            }
            
            // Handle graceful shutdown signal
            _ = &mut shutdown => {
                tracing::info!("shutting down DNS server");
                break Ok(());
            }
        }
    }
}
```

#### Timeout Handling

```rust
use tokio::time::{timeout, Duration};

async fn query_upstream(server: &str, query: &DnsQuery) -> Result<DnsResponse> {
    // Enforce 5-second timeout on upstream query
    let response = timeout(
        Duration::from_secs(5),
        send_query(server, query)
    )
    .await
    .map_err(|_| DnsError::Timeout(5))??;  // Double ? for nested Result
    
    Ok(response)
}
```

#### Concurrent Operations

```rust
use tokio::try_join;

async fn query_multiple_servers(
    servers: &[String],
    query: &DnsQuery,
) -> Result<DnsResponse> {
    // Query all servers concurrently, return first success
    let futures = servers.iter().map(|server| {
        query_upstream(server, query)
    });
    
    // Wait for first successful response
    let (result,) = try_join!(futures)?;
    Ok(result)
}
```

#### Resource Cleanup

```rust
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

async fn save_lease_database(leases: &[DhcpLease]) -> Result<()> {
    // File automatically closed when dropped
    let mut file = File::create("/var/lib/dnsmasq/leases").await?;
    
    for lease in leases {
        let line = format!("{}\n", lease.to_string());
        file.write_all(line.as_bytes()).await?;
    }
    
    // Ensure data is flushed to disk
    file.sync_all().await?;
    
    Ok(())
}
```

### Error Handling in Async Code

```rust
async fn process_with_retry(query: &DnsQuery) -> Result<DnsResponse> {
    let mut attempts = 0;
    let max_attempts = 3;
    
    loop {
        attempts += 1;
        
        match query_upstream("8.8.8.8", query).await {
            Ok(response) => return Ok(response),
            Err(e) if attempts < max_attempts => {
                tracing::warn!("attempt {} failed: {}, retrying", attempts, e);
                tokio::time::sleep(Duration::from_millis(100 * attempts)).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}
```

### Spawning Tasks

```rust
use tokio::task::JoinHandle;

async fn handle_client_connections() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:53").await?;
    let mut tasks: Vec<JoinHandle<Result<()>>> = Vec::new();
    
    loop {
        let (stream, addr) = listener.accept().await?;
        
        // Spawn task for each connection
        let handle = tokio::spawn(async move {
            tracing::debug!("connection from {}", addr);
            handle_connection(stream).await
        });
        
        tasks.push(handle);
        
        // Clean up completed tasks
        tasks.retain(|task| !task.is_finished());
    }
}
```

## Platform-Specific Code

The project supports multiple platforms through conditional compilation.

### Conditional Compilation

Use `cfg` attributes for platform-specific code:

```rust
// src/platform/mod.rs
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub mod bsd;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
)))]
pub mod generic;

// Re-export platform-specific implementation
#[cfg(target_os = "linux")]
pub use linux::NetworkInterface;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub use bsd::NetworkInterface;

#[cfg(target_os = "macos")]
pub use macos::NetworkInterface;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
)))]
pub use generic::NetworkInterface;
```

### Platform Traits

Define common traits for platform-specific implementations:

```rust
// src/platform/traits.rs
pub trait NetworkInterface {
    /// Create a new network interface
    fn new() -> Result<Self> where Self: Sized;
    
    /// Get all network interfaces on the system
    fn enumerate() -> Result<Vec<InterfaceInfo>>;
    
    /// Bind to a specific interface
    fn bind(&mut self, name: &str) -> Result<()>;
    
    /// Send packet on this interface
    fn send(&self, packet: &[u8]) -> Result<usize>;
    
    /// Receive packet from this interface
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
}

// Platform-specific implementation
#[cfg(target_os = "linux")]
impl NetworkInterface for LinuxNetworkInterface {
    fn new() -> Result<Self> {
        // Linux-specific implementation using netlink
        let socket = create_netlink_socket()?;
        Ok(LinuxNetworkInterface { socket })
    }
    
    // ... other trait methods
}
```

### Feature Flags

Use Cargo features for optional platform functionality:

```rust
// Cargo.toml
[features]
default = ["dns", "dhcp"]

# Linux-specific features
netlink = []
inotify = []
ipset = []
nftables = ["dep:nftables"]

# BSD-specific features
bpf = []
kqueue = []

# macOS-specific features
launchd = []

// src/platform/linux/mod.rs
#[cfg(feature = "netlink")]
pub mod netlink;

#[cfg(feature = "inotify")]
pub mod inotify;

#[cfg(feature = "ipset")]
pub mod ipset;

#[cfg(feature = "nftables")]
pub mod nftset;
```

### Testing Platform-Specific Code

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[cfg(target_os = "linux")]
    fn test_netlink_socket_creation() {
        let socket = create_netlink_socket().unwrap();
        assert!(socket.as_raw_fd() > 0);
    }
    
    #[test]
    #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    fn test_bpf_interface() {
        let interface = BpfInterface::new().unwrap();
        assert!(interface.is_open());
    }
    
    #[test]
    fn test_generic_fallback() {
        // This test runs on all platforms
        let info = get_interface_info("lo").unwrap();
        assert!(!info.name.is_empty());
    }
}
```

## Review Checklist

Before submitting a pull request, verify all items on this checklist:

### Code Quality

- [ ] Code follows rustfmt configuration (`cargo fmt --all`)
- [ ] Clippy passes with no warnings (`cargo clippy --all-features -- -D warnings`)
- [ ] No compiler warnings (`cargo build --all-features`)
- [ ] No use of `unwrap()` or `expect()` in production code
- [ ] No `panic!()` in production code paths
- [ ] All `unsafe` blocks have safety documentation (platform FFI only)

### Testing

- [ ] All tests pass (`cargo test --all-features`)
- [ ] New code has unit tests with >80% coverage
- [ ] Integration tests added for new features
- [ ] Property-based tests for protocol code
- [ ] Coverage measured (`cargo tarpaulin --fail-under 80`)
- [ ] Benchmarks added for performance-critical code

### Documentation

- [ ] Public APIs have rustdoc comments
- [ ] Modules have `//!` documentation
- [ ] Complex algorithms have explanatory comments
- [ ] Migration notes for C implementation differences
- [ ] Examples provided for non-obvious usage
- [ ] CHANGELOG.md updated

### Memory Safety

- [ ] No `unsafe` blocks in core logic (DNS/DHCP/TFTP)
- [ ] All `unsafe` blocks justified with safety comments
- [ ] Ownership patterns used correctly (Arc, Rc, Box)
- [ ] No potential for buffer overflows
- [ ] No manual memory management

### Protocol Compliance

- [ ] Network behavior matches C implementation
- [ ] Packet formats byte-identical to C version
- [ ] Timing characteristics preserved
- [ ] Configuration file compatibility maintained
- [ ] Command-line arguments work identically

### Platform Support

- [ ] Conditional compilation correct (`#[cfg(...)]`)
- [ ] Feature flags properly gated
- [ ] Platform-specific code documented
- [ ] Tests pass on target platforms (Linux, BSD, macOS)

### Security

- [ ] Input validation for all network data
- [ ] No SQL injection vulnerabilities (if using database)
- [ ] No path traversal vulnerabilities (TFTP)
- [ ] Privilege dropping implemented correctly
- [ ] Security audit passing (`cargo audit`)

### Git and PR

- [ ] Commit messages follow conventional format
- [ ] PR title is clear and descriptive
- [ ] PR description explains what and why
- [ ] Related issues referenced
- [ ] No merge conflicts with main branch
- [ ] Branch is up to date with main

### CI/CD

- [ ] All CI checks passing
- [ ] Build succeeds on all target platforms
- [ ] Tests pass in CI environment
- [ ] Coverage meets threshold (>80%)
- [ ] No security vulnerabilities detected

---

## Additional Resources

- [Rust Book](https://doc.rust-lang.org/book/) - Official Rust programming language book
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) - Best practices for API design
- [Tokio Documentation](https://tokio.rs/tokio/tutorial) - Async runtime documentation
- [Clippy Lints](https://rust-lang.github.io/rust-clippy/master/) - Complete list of clippy lints
- [C to Rust Translation Guide](../MIGRATION.md) - Project-specific migration patterns

## Questions?

If you have questions about contributing:

1. Check existing documentation in `docs/rust/`
2. Search for related issues on GitHub
3. Ask in project discussions or chat
4. Open an issue with the `question` label

Thank you for contributing to dnsmasq-rs! 🦀
