# dnsmasq

**Lightweight DNS forwarder and DHCP/DHCPv6/TFTP server**

dnsmasq provides network infrastructure services for small to medium-sized networks. It is designed to be lightweight, easy to configure, and suitable for resource-constrained environments including embedded systems, home routers, and development machines.

## Overview

dnsmasq combines DNS forwarding, DNS caching, DHCPv4/DHCPv6 servers, TFTP server, and IPv6 Router Advertisement into a single, efficient daemon. This repository contains both the original C implementation and a memory-safe Rust implementation that provides drop-in replacement capability.

### Key Capabilities

- **DNS Forwarding & Caching**: Forward DNS queries to upstream servers with integrated caching for improved performance
- **DHCP Services**: Full-featured DHCPv4 and DHCPv6 servers with lease management and vendor option support
- **TFTP Server**: Network boot support for PXE environments
- **DNSSEC Validation**: Cryptographic validation of DNS responses per RFCs 4033/4034/4035
- **Router Advertisement**: IPv6 RA and SLAAC support per RFCs 4861/4862
- **Platform Support**: Linux, FreeBSD, OpenBSD, NetBSD, macOS, Solaris, and Android

### Why Two Implementations?

The **C implementation** is the mature, battle-tested version used in production worldwide. The **Rust implementation** is a memory-safe refactoring that eliminates buffer overflows, use-after-free, and null pointer dereference vulnerabilities while maintaining 100% functional equivalence and configuration compatibility.

## Quick Start - C Version

The traditional C implementation uses a make-based build system.

### Prerequisites

- GCC or Clang compiler
- GNU Make
- Optional: libnettle/libhogweed (DNSSEC), libdbus-1 (D-Bus), libidn2 (IDN)

### Build and Install

```bash
# Build with default features
make

# Build with DNSSEC support
make COPTS="-DHAVE_DNSSEC"

# Install (requires root)
sudo make install

# Install to custom prefix
make PREFIX=/opt/dnsmasq install
```

### Run

```bash
# Run with default configuration
sudo dnsmasq

# Run with custom config file
sudo dnsmasq -C /etc/dnsmasq.conf

# Run in foreground (no daemon)
sudo dnsmasq -d

# Test configuration
dnsmasq --test
```

See [docs/BUILDING.md](docs/BUILDING.md) for detailed build instructions including platform-specific requirements.

## Quick Start - Rust Version

The Rust implementation provides memory safety guarantees while maintaining full compatibility with existing configurations.

### Prerequisites

- **Rust 1.91.0** (install via [rustup](https://rustup.rs/))
- Cargo (included with Rust)
- Optional system libraries: libnetfilter_conntrack, libnftables, libubus (same as C version)

### Build and Install

```bash
# Build optimized release binary
cargo build --release

# Run tests to validate build
cargo test

# Run integration tests
cargo test --test '*'

# Install binary (release build recommended)
sudo cp target/release/dnsmasq /usr/local/sbin/dnsmasq

# Or install via cargo
cargo install --path .
```

### Binary Location

After `cargo build --release`, the binary is located at:
```
target/release/dnsmasq
```

### Configuration Compatibility

The Rust implementation uses **identical configuration syntax** to the C version. Your existing `dnsmasq.conf` files work without modification:

```bash
# Use existing C configuration unchanged
sudo target/release/dnsmasq -C /etc/dnsmasq.conf

# All command-line flags are identical
sudo target/release/dnsmasq -d -q -p 5353 --log-queries
```

### Cargo Features

Enable optional features at build time:

```bash
# Build with DNSSEC support (default: enabled)
cargo build --release --features dnssec

# Build with D-Bus integration
cargo build --release --features dbus

# Build with all optional features
cargo build --release --all-features

# Build minimal (DNS/DHCP only, no optional features)
cargo build --release --no-default-features --features dhcp,dhcp6
```

See [docs/BUILDING.md](docs/BUILDING.md) for complete Rust build documentation.

## Docker Deployment

Pre-built Docker images are available for containerized deployment using Alpine Linux as the base.

### Supported Alpine Versions

- Alpine Linux 3.19.9
- Alpine Linux 3.20.8
- Alpine Linux 3.21.5
- Alpine Linux 3.22.2

### Build Container Image

```bash
# Build from provided Dockerfile
docker build -f docker/Dockerfile.alpine -t dnsmasq:latest .

# Build with specific Alpine version
docker build -f docker/Dockerfile.alpine --build-arg ALPINE_VERSION=3.22.2 -t dnsmasq:alpine3.22 .
```

### Run Container

```bash
# Run with default configuration
docker run -d \
  --name dnsmasq \
  --cap-add=NET_ADMIN \
  --net=host \
  dnsmasq:latest

# Run with custom configuration
docker run -d \
  --name dnsmasq \
  --cap-add=NET_ADMIN \
  --net=host \
  -v /path/to/dnsmasq.conf:/etc/dnsmasq.conf:ro \
  -v /var/lib/misc:/var/lib/misc \
  dnsmasq:latest

# Run with command-line options
docker run -d \
  --name dnsmasq \
  --cap-add=NET_ADMIN \
  -p 53:53/udp \
  -p 53:53/tcp \
  dnsmasq:latest --no-daemon --log-queries --server=8.8.8.8
```

### Container Notes

- `--cap-add=NET_ADMIN` required for DHCP server functionality
- `--net=host` recommended for optimal performance and full feature access
- Volume mount `/var/lib/misc` to persist DHCP leases across container restarts
- The container uses the Rust implementation by default

See [docker/README.md](docker/README.md) for container-specific configuration guidance.

## Features

### DNS Services

- **Recursive DNS Resolution**: Forward queries to upstream DNS servers
- **DNS Caching**: High-performance cache with LRU eviction and negative caching
- **DNSSEC Validation**: Cryptographic validation with trust anchor management
- **Domain Blocking**: Block advertising and malicious domains
- **Local Domain Resolution**: Serve authoritative DNS for local domains
- **Conditional Forwarding**: Route queries to specific upstreams based on domain
- **DNS Rebind Protection**: Prevent DNS rebinding attacks
- **EDNS0 Support**: Extended DNS with larger UDP packet sizes

### DHCP Services

- **DHCPv4 Server**: RFC 2131/2132 compliant with vendor options
- **DHCPv6 Server**: RFC 3315 compliant with IA_NA, IA_TA, IA_PD
- **Static and Dynamic Leases**: Mixed static/dynamic address allocation
- **Lease Persistence**: Survive daemon restarts with lease database
- **Vendor-Specific Options**: Support for PXE boot, TFTP, and custom vendor options
- **Netboot/PXE**: Network boot support for diskless clients
- **Integration with DNS**: Automatic A/AAAA record creation for DHCP clients
- **DHCP Relay**: DHCP relay agent functionality

### IPv6 Services

- **Router Advertisement (RA)**: RFC 4861 compliant RA server
- **SLAAC Support**: Stateless Address Autoconfiguration per RFC 4862
- **DHCPv6 Integration**: Coordinated DHCPv6 and RA operation
- **Prefix Delegation**: DHCPv6-PD for delegating IPv6 prefixes

### Additional Services

- **TFTP Server**: RFC 1350 compliant with OACK/blksize extensions
- **Network Boot**: PXE boot support for OS installation and diskless clients

### External Integrations

- **D-Bus Interface**: Control and monitoring via D-Bus (Linux)
- **ubus Interface**: OpenWrt ubus integration
- **inotify/kqueue**: Automatic configuration reload on file changes
- **ipset Integration**: Populate ipset rules based on DNS queries (Linux)
- **nftables Integration**: Populate nftables sets (Linux)
- **PF Tables**: Populate PF tables (BSD)
- **conntrack**: Linux connection tracking integration
- **Script Execution**: Execute external scripts on DHCP lease events

### Platform Support

- **Linux**: Full feature support including netlink, inotify, conntrack, ipset/nftables
- **FreeBSD/OpenBSD/NetBSD**: BSD routing sockets, PF tables, kqueue
- **macOS**: Core DNS/DHCP/TFTP functionality
- **Solaris**: Core functionality with Solaris-specific network APIs
- **Android**: NDK build support for Android integration

## Configuration

### Basic Configuration File

Create `/etc/dnsmasq.conf`:

```
# Listen on specific interface
interface=eth0

# Upstream DNS servers
server=8.8.8.8
server=8.8.4.4

# DHCP range
dhcp-range=192.168.1.50,192.168.1.150,12h

# DNS cache size
cache-size=10000

# Log queries (for debugging)
log-queries
```

### Configuration Files

- **Default configuration**: `/etc/dnsmasq.conf`
- **Example configuration**: `dnsmasq.conf.example` (in source repository)
- **Configuration directory**: `/etc/dnsmasq.d/` (include directory)

### Common Configuration Options

| Option | Purpose |
|--------|---------|
| `server=<IP>` | Specify upstream DNS server |
| `interface=<name>` | Listen on specific interface |
| `dhcp-range=<start>,<end>,<lease>` | Configure DHCP address pool |
| `dhcp-option=<opt>,<value>` | Set DHCP option |
| `cache-size=<n>` | Set DNS cache size (default 150) |
| `no-daemon` | Run in foreground (don't daemonize) |
| `log-queries` | Log DNS queries |
| `log-dhcp` | Log DHCP transactions |
| `conf-file=<file>` | Additional configuration file |
| `conf-dir=<dir>` | Include all files in directory |

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for comprehensive configuration documentation.

## Documentation

### User Documentation

- **[dnsmasq.conf.example](dnsmasq.conf.example)**: Annotated example configuration file
- **[doc.html](doc.html)**: Complete user manual (HTML format)
- **[setup.html](setup.html)**: Deployment and integration guide

### Developer Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**: System architecture overview (C implementation reference)
- **[docs/RUST_ARCHITECTURE.md](docs/RUST_ARCHITECTURE.md)**: Rust implementation architecture
- **[docs/BUILDING.md](docs/BUILDING.md)**: Build instructions for C and Rust
- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**: Configuration system internals
- **[docs/DNS_FORWARDING.md](docs/DNS_FORWARDING.md)**: DNS forwarding implementation
- **[docs/DNS_CACHING.md](docs/DNS_CACHING.md)**: DNS caching algorithm
- **[docs/DHCP_V4.md](docs/DHCP_V4.md)**: DHCPv4 server implementation
- **[docs/DHCP_V6.md](docs/DHCP_V6.md)**: DHCPv6 server implementation
- **[docs/DNSSEC.md](docs/DNSSEC.md)**: DNSSEC validation implementation
- **[docs/TFTP.md](docs/TFTP.md)**: TFTP server implementation
- **[docs/README.md](docs/README.md)**: Developer documentation index

### Migration Documentation

- **[MIGRATION.md](MIGRATION.md)**: Guide for migrating from C to Rust implementation
- **[CHANGELOG.md](CHANGELOG.md)**: Version history and release notes

## Testing

### C Implementation Tests

```bash
# Run existing test suite
make test

# Run specific test
make test-dhcp
```

### Rust Implementation Tests

```bash
# Run all unit tests
cargo test

# Run integration tests
cargo test --test '*'

# Run with verbose output
cargo test -- --nocapture

# Run specific test module
cargo test dns::cache

# Run benchmarks
cargo bench

# Check code coverage (requires cargo-tarpaulin)
cargo tarpaulin --out Html
```

### Compatibility Testing

```bash
# Validate C and Rust produce identical behavior
./scripts/test-compat.sh

# Validate configuration migration
cargo run --bin dnsmasq-migrate-config -- /etc/dnsmasq.conf
```

## Performance

### Benchmarks

| Metric | C Implementation | Rust Implementation | Notes |
|--------|------------------|---------------------|-------|
| DNS Query Throughput | >10,000 qps | >10,000 qps | Comparable performance |
| DHCP Lease Allocation | >5,000 leases/sec | >5,000 leases/sec | Synthetic test with perfdhcp |
| Memory Footprint | 8-12 MB | 9-14 MB | Within 20% baseline |
| Binary Size (stripped) | ~500 KB | ~2.5 MB | Rust includes runtime |
| Startup Time | <50ms | <100ms | Within target |

Performance measured on Linux x86_64 with default cache size. Actual performance varies by configuration and workload.

## Security

### Memory Safety

The **Rust implementation** eliminates entire classes of memory-safety vulnerabilities:

- **Buffer overflows**: Prevented by Rust's bounds checking
- **Use-after-free**: Prevented by ownership system
- **Double-free**: Prevented by automatic memory management
- **Null pointer dereferences**: Prevented by Option<T> types
- **Data races**: Prevented by borrow checker

The **C implementation** relies on careful manual memory management and defensive programming practices.

### DNSSEC

Both implementations support DNSSEC validation:

- RSA, ECDSA, Ed25519 signature algorithms
- Trust anchor management
- Automatic key rollover handling
- NSEC/NSEC3 proof validation

### Privilege Separation

Both implementations support privilege dropping after binding to privileged ports:

```bash
# Run as unprivileged user after startup
dnsmasq --user=dnsmasq --group=dnsmasq
```

## Contributing

### Reporting Issues

Please report bugs, security issues, and feature requests to:
- **Email**: simon@thekelleys.org.uk
- **Mailing List**: dnsmasq-discuss@lists.thekelleys.org.uk

### Development

Contributions are welcome. Please:
1. Review [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for C codebase or [docs/RUST_ARCHITECTURE.md](docs/RUST_ARCHITECTURE.md) for Rust codebase
2. Follow existing code style and conventions
3. Include tests for new features
4. Update documentation as appropriate

### Code Style

- **C code**: Follow existing K&R-derived style with 2-space indentation
- **Rust code**: Use `rustfmt` for formatting (`cargo fmt`)
- **Rust code**: Pass `clippy` lints (`cargo clippy`)

## License

dnsmasq is dual-licensed:

- **GNU General Public License v2.0 or later** (GPL-2.0-or-later)
- **GNU General Public License v3.0 or later** (GPL-3.0-or-later)

You may choose either license for your use of dnsmasq.

See [COPYING](COPYING) and [COPYING-v3](COPYING-v3) for full license texts.

## Authors and Maintainers

**Original Author and Maintainer**: Simon Kelley <simon@thekelleys.org.uk>

**Rust Implementation**: Memory-safe refactoring preserving original design and behavior

## Links

- **Official Website**: http://www.thekelleys.org.uk/dnsmasq/doc.html
- **Git Repository**: http://thekelleys.org.uk/gitweb/?p=dnsmasq.git
- **Mailing List**: http://lists.thekelleys.org.uk/mailman/listinfo/dnsmasq-discuss

## System Integration

### systemd

Service files are provided for systemd integration:

```bash
# Install systemd service (Rust version)
sudo cp systemd/dnsmasq-rust.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dnsmasq-rust
sudo systemctl start dnsmasq-rust

# Check status
sudo systemctl status dnsmasq-rust
```

### OpenWrt

dnsmasq is the default DNS/DHCP server in OpenWrt and integrates with ubus for configuration and monitoring.

### Android

Build for Android NDK using:

```bash
# C implementation
ndk-build -C . NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk

# Rust implementation (requires Android NDK with Rust targets)
cargo build --target aarch64-linux-android --release
```

## Acknowledgments

dnsmasq is used in millions of deployments worldwide including:

- Home routers and access points
- OpenWrt/DD-WRT/Tomato firmware
- Docker and container environments
- Enterprise network infrastructure
- IoT and embedded devices
- Development and testing environments

Thank you to all contributors, testers, and users who have helped make dnsmasq robust and reliable.
