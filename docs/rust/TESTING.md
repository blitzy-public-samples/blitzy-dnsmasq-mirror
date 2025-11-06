# dnsmasq-rs Testing Strategy

## Overview

The dnsmasq-rs testing strategy ensures memory safety, protocol compliance, and functional equivalence with the C implementation through multiple layers of testing:

1. **Unit Tests** - >80% code coverage target (Section 0.7.4)
2. **Integration Tests** - Protocol compliance (DNS, DHCP, TFTP)
3. **Property-Based Tests** - Round-trip and invariant verification
4. **Benchmarks** - Performance regression detection
5. **Acceptance Tests** - C test suite compatibility

## Test Organization

### Directory Structure

```
dnsmasq-rs/
├── src/
│   ├── **/*.rs           - Unit tests in #[cfg(test)] modules
│   └── lib.rs            - Test utilities re-exports
│
├── tests/
│   ├── integration/
│   │   ├── dns_tests.rs          - DNS protocol compliance
│   │   ├── dhcp_tests.rs         - DHCP v4/v6 protocol tests
│   │   ├── tftp_tests.rs         - TFTP functionality tests
│   │   ├── config_tests.rs       - Configuration parsing tests
│   │   ├── lease_tests.rs        - Lease persistence tests
│   │   └── platform_tests.rs     - Platform-specific tests
│   │
│   └── fixtures/
│       ├── config/               - Sample dnsmasq.conf files
│       ├── zones/                - DNS zone files
│       └── leases/               - Sample lease files
│
├── benches/
│   ├── dns_cache.rs              - Cache performance
│   ├── dhcp_allocation.rs        - Lease allocation
│   ├── packet_parsing.rs         - Protocol parsing
│   └── forwarding.rs             - DNS forwarding
│
└── Cargo.toml                     - Test dependencies
```

## Unit Testing

### Coverage Target: >80% (Section 0.7.4)

Unit tests are embedded in each module using `#[cfg(test)]` blocks and should test all public APIs and critical internal logic.

### Example Unit Test

```rust
// src/dns/cache.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_cache_insert_and_lookup() {
        let mut cache = DnsCache::new(100);
        let query = DnsQuery::new("example.com", RecordType::A);
        let record = DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1));
        
        cache.insert(&query, record.clone(), 300).unwrap();
        
        assert_eq!(cache.lookup(&query), Some(&record));
    }
    
    #[test]
    fn test_cache_expiration() {
        let mut cache = DnsCache::new(100);
        let query = DnsQuery::new("example.com", RecordType::A);
        let record = DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1));
        
        // Insert with 0 TTL (immediate expiration)
        cache.insert(&query, record, 0).unwrap();
        
        // Expire entries
        cache.expire_old_entries();
        
        // Should be removed
        assert_eq!(cache.lookup(&query), None);
    }
    
    #[test]
    fn test_cache_lru_eviction() {
        let mut cache = DnsCache::new(2); // Max 2 entries
        
        let q1 = DnsQuery::new("example1.com", RecordType::A);
        let q2 = DnsQuery::new("example2.com", RecordType::A);
        let q3 = DnsQuery::new("example3.com", RecordType::A);
        
        let r1 = DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1));
        let r2 = DnsRecord::A(Ipv4Addr::new(192, 0, 2, 2));
        let r3 = DnsRecord::A(Ipv4Addr::new(192, 0, 2, 3));
        
        cache.insert(&q1, r1.clone(), 300).unwrap();
        cache.insert(&q2, r2.clone(), 300).unwrap();
        cache.insert(&q3, r3.clone(), 300).unwrap(); // Should evict q1
        
        assert_eq!(cache.lookup(&q1), None); // Evicted (LRU)
        assert_eq!(cache.lookup(&q2), Some(&r2));
        assert_eq!(cache.lookup(&q3), Some(&r3));
    }
}
```

### Running Unit Tests

```bash
# Run all unit tests
cargo test

# Run tests for specific module
cargo test dns::cache

# Run with logging output
cargo test -- --nocapture

# Run tests in parallel
cargo test -- --test-threads=4

# Run with all features
cargo test --all-features
```

## Integration Testing

### Protocol Compliance Tests

Integration tests verify protocol-level behavior and compatibility with existing implementations.

#### DNS Protocol Tests

```rust
// tests/integration/dns_tests.rs
use dnsmasq::{dns, config::ConfigBuilder};
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_dns_query_response() {
    // Start test DNS server
    let config = ConfigBuilder::new()
        .with_dns_port(15353)
        .with_upstream_servers(vec!["8.8.8.8:53".parse().unwrap()])
        .build()
        .unwrap();
    
    let server_handle = tokio::spawn(async move {
        dns::server::start(config).await
    });
    
    // Send DNS query
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = dns::protocol::DnsMessage::query("example.com", dns::RecordType::A);
    let query_bytes = query.serialize().unwrap();
    
    socket.send_to(&query_bytes, "127.0.0.1:15353").await.unwrap();
    
    // Receive response
    let mut buf = vec![0u8; 4096];
    let (len, _) = socket.recv_from(&mut buf).await.unwrap();
    let response = dns::protocol::DnsMessage::parse(&buf[..len]).unwrap();
    
    // Verify response
    assert_eq!(response.header.response_code, dns::ResponseCode::NoError);
    assert!(!response.answers.is_empty());
    
    server_handle.abort();
}

#[tokio::test]
async fn test_dns_cache_hit() {
    // Test that repeated queries are served from cache
    let config = ConfigBuilder::new()
        .with_dns_port(15354)
        .build()
        .unwrap();
    
    let server_handle = tokio::spawn(async move {
        dns::server::start(config).await
    });
    
    // First query (cache miss)
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = dns::protocol::DnsMessage::query("cached.example.com", dns::RecordType::A);
    let query_bytes = query.serialize().unwrap();
    
    let start = std::time::Instant::now();
    socket.send_to(&query_bytes, "127.0.0.1:15354").await.unwrap();
    let mut buf = vec![0u8; 4096];
    socket.recv_from(&mut buf).await.unwrap();
    let first_duration = start.elapsed();
    
    // Second query (cache hit - should be faster)
    let start = std::time::Instant::now();
    socket.send_to(&query_bytes, "127.0.0.1:15354").await.unwrap();
    let mut buf = vec![0u8; 4096];
    socket.recv_from(&mut buf).await.unwrap();
    let second_duration = start.elapsed();
    
    // Cache hit should be faster
    assert!(second_duration < first_duration);
    
    server_handle.abort();
}
```

#### DHCP Protocol Tests

```rust
// tests/integration/dhcp_tests.rs
use dnsmasq::dhcp::{v4, DhcpConfig};

#[tokio::test]
async fn test_dhcp_discover_offer() {
    let config = DhcpConfig::new()
        .with_range("192.168.1.100".parse().unwrap(), "192.168.1.200".parse().unwrap())
        .with_lease_time(3600);
    
    let mut server = v4::DhcpV4Server::new(config);
    
    // Create DISCOVER packet
    let discover = v4::DhcpMessage::discover(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into()
    );
    let discover_bytes = discover.serialize().unwrap();
    
    // Process DISCOVER
    let response = server.handle_packet(&discover_bytes, "0.0.0.0:68".parse().unwrap())
        .await
        .unwrap()
        .expect("Expected OFFER response");
    
    // Parse OFFER
    let offer = v4::DhcpMessage::parse(&response).unwrap();
    assert_eq!(offer.message_type(), v4::MessageType::Offer);
    assert!(offer.your_ip().is_some());
}

#[tokio::test]
async fn test_dhcp_lease_persistence() {
    use tempfile::TempDir;
    
    let temp_dir = TempDir::new().unwrap();
    let lease_file = temp_dir.path().join("dnsmasq.leases");
    
    // Create lease database
    let mut db = dhcp::lease::LeaseDatabase::new();
    let lease = dhcp::lease::Lease {
        mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into(),
        ip: "192.168.1.100".parse().unwrap(),
        expires_at: 1234567890,
        hostname: Some("test-host".to_string()),
    };
    db.upsert_lease(lease.clone());
    
    // Save to file
    db.save(&lease_file).unwrap();
    
    // Load from file
    let loaded_db = dhcp::lease::LeaseDatabase::load(&lease_file).unwrap();
    let loaded_lease = loaded_db.find_by_mac(&lease.mac).unwrap();
    
    assert_eq!(loaded_lease.ip, lease.ip);
    assert_eq!(loaded_lease.expires_at, lease.expires_at);
}
```

### Running Integration Tests

```bash
# Run all integration tests
cargo test --test '*'

# Run specific integration test
cargo test --test dns_tests

# Run with all features
cargo test --test '*' --all-features

# Run with logging
RUST_LOG=debug cargo test --test '*' -- --nocapture
```

## Property-Based Testing (Section 0.7.4)

Property-based tests verify invariants and round-trip properties using `proptest`.

### DNS Protocol Round-Trip

```rust
// src/dns/protocol.rs
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn dns_message_roundtrip(query_name in "[a-z]{1,63}\\.[a-z]{2,6}") {
            let original = DnsMessage::query(&query_name, RecordType::A);
            let serialized = original.serialize().unwrap();
            let parsed = DnsMessage::parse(&serialized).unwrap();
            
            prop_assert_eq!(original, parsed);
        }
        
        #[test]
        fn dns_no_panic_on_malformed_input(data in prop::collection::vec(any::<u8>(), 0..4096)) {
            // Should never panic, even on malformed input
            let _ = DnsMessage::parse(&data);
        }
    }
}
```

### DHCP Protocol Invariants

```rust
// src/dhcp/v4/protocol.rs
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn dhcp_message_roundtrip(
            mac in prop::array::uniform6(any::<u8>()),
            xid in any::<u32>(),
        ) {
            let original = DhcpMessage::discover(mac.into()).with_xid(xid);
            let serialized = original.serialize().unwrap();
            let parsed = DhcpMessage::parse(&serialized).unwrap();
            
            prop_assert_eq!(original.xid(), parsed.xid());
            prop_assert_eq!(original.client_mac(), parsed.client_mac());
        }
    }
}
```

### Running Property Tests

```bash
# Run property-based tests
cargo test --features proptest-impl

# Run with more cases
PROPTEST_CASES=10000 cargo test --features proptest-impl
```

## Benchmarking

Performance regression detection using `criterion`.

### DNS Cache Benchmark

```rust
// benches/dns_cache.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dnsmasq::dns::cache::DnsCache;

fn cache_insert_benchmark(c: &mut Criterion) {
    c.bench_function("cache insert", |b| {
        let mut cache = DnsCache::new(10000);
        let query = DnsQuery::new("example.com", RecordType::A);
        let record = DnsRecord::A("192.0.2.1".parse().unwrap());
        
        b.iter(|| {
            cache.insert(black_box(&query), black_box(record.clone()), 300).unwrap()
        });
    });
}

fn cache_lookup_benchmark(c: &mut Criterion) {
    let mut cache = DnsCache::new(10000);
    for i in 0..1000 {
        let query = DnsQuery::new(&format!("example{}.com", i), RecordType::A);
        let record = DnsRecord::A("192.0.2.1".parse().unwrap());
        cache.insert(&query, record, 300).unwrap();
    }
    
    c.bench_function("cache lookup", |b| {
        let query = DnsQuery::new("example500.com", RecordType::A);
        b.iter(|| cache.lookup(black_box(&query)));
    });
}

criterion_group!(benches, cache_insert_benchmark, cache_lookup_benchmark);
criterion_main!(benches);
```

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench dns_cache

# Generate HTML report
cargo bench --bench dns_cache -- --save-baseline main

# Compare with baseline
cargo bench --bench dns_cache -- --baseline main
```

## Mocking and Test Utilities

### Mocking External Dependencies

```rust
// src/network/socket.rs
#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
pub trait SocketProvider {
    async fn create_socket(&self, port: u16) -> Result<UdpSocket, io::Error>;
}

// In tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_with_mock_socket() {
        let mut mock = MockSocketProvider::new();
        mock.expect_create_socket()
            .returning(|_| Ok(test_socket()));
        
        // Use mock in test
    }
}
```

### Test Fixtures

```rust
// tests/fixtures.rs
pub fn test_dns_query() -> DnsQuery {
    DnsQuery::new("test.example.com", RecordType::A)
}

pub fn test_dhcp_lease() -> Lease {
    Lease {
        mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into(),
        ip: "192.168.1.100".parse().unwrap(),
        expires_at: 1234567890,
        hostname: Some("test-host".to_string()),
    }
}
```

## Coverage Measurement

### Target: >80% Code Coverage (Section 0.7.4)

```bash
# Install cargo-tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage/

# Generate coverage with all features
cargo tarpaulin --all-features --out Html --output-dir coverage/

# View coverage report
open coverage/index.html  # macOS
xdg-open coverage/index.html  # Linux

# CI-friendly output
cargo tarpaulin --out Xml --output-dir coverage/
```

### Coverage Requirements

- **Overall:** >80% line coverage
- **Core modules:** >90% coverage (dns, dhcp, config)
- **Platform-specific:** Best effort (may be lower due to FFI)
- **Test utilities:** Not counted toward coverage

## Acceptance Testing

### C Test Suite Compatibility

The Rust implementation must pass all existing C test suites (Section 0.7.4):

```bash
# Run dnsmasq C test suite against Rust binary
cd dnsmasq-test/
./run_tests.sh --binary=../target/release/dnsmasq-rs

# Expected: All tests pass with identical behavior
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Rust CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: 1.91.0
          override: true
      
      # Unit tests
      - name: Run tests
        run: cargo test --all-features
      
      # Integration tests
      - name: Run integration tests
        run: cargo test --test '*' --all-features
      
      # Property tests
      - name: Run property tests
        run: cargo test --features proptest-impl
        env:
          PROPTEST_CASES: 1000
      
      # Coverage
      - name: Generate coverage
        run: |
          cargo install cargo-tarpaulin
          cargo tarpaulin --all-features --out Xml
      
      # Upload coverage
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./cobertura.xml
      
      # Benchmarks (no regression)
      - name: Run benchmarks
        run: cargo bench --no-run
```

## Test Execution Summary

```bash
# Complete test suite
make test-all() {
    cargo fmt --all -- --check                    # Format check
    cargo clippy --all-features -- -D warnings   # Linting
    cargo test --all-features                    # Unit tests
    cargo test --test '*' --all-features         # Integration tests
    cargo test --features proptest-impl          # Property tests
    cargo tarpaulin --all-features --out Html    # Coverage
    cargo bench                                  # Benchmarks
}
```

## Related Documentation

- [Contributing](CONTRIBUTING.md) - Coding standards and PR process
- [API](API.md) - Public API reference
- [Architecture](ARCHITECTURE.md) - System design
- [Building](BUILDING.md) - Build instructions

---

**Testing ensures memory safety, protocol compliance, and functional equivalence with the C implementation.**
