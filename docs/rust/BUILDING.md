# Building dnsmasq-rs

Comprehensive build system documentation for the dnsmasq Rust implementation covering platform-specific compilation, dependency management, feature selection, cross-compilation, and troubleshooting.

## Table of Contents

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Platform-Specific Instructions](#platform-specific-instructions)
- [Feature Flags](#feature-flags)
- [Build Profiles](#build-profiles)
- [Cross-Compilation](#cross-compilation)
- [Docker Builds](#docker-builds)
- [Static vs Dynamic Linking](#static-vs-dynamic-linking)
- [Troubleshooting](#troubleshooting)
- [CI/CD Integration](#cicd-integration)

---

## Quick Start

For most users, the standard build is straightforward:

```bash
# Clone repository
git clone https://github.com/your-org/dnsmasq.git
cd dnsmasq

# Build with default features (DNS, DHCP, TFTP)
cargo build --release

# Binary location
./target/release/dnsmasq-rs --version

# Install to system
sudo cargo install --path . --features default
```

---

## Prerequisites

### Rust Toolchain

**Required:** Rust 1.91.0 (stable channel) per Section 0.1.2

The project includes `rust-toolchain.toml` which automatically installs the correct version:

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Rust toolchain installed automatically via rust-toolchain.toml
cd dnsmasq
cargo --version
# Output: cargo 1.91.0 (stable)
```

### Build Tools

#### All Platforms
- **Cargo** - Rust package manager (bundled with Rust)
- **Git** - For cloning repository

#### Linux
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev

# Red Hat/CentOS/Fedora
sudo yum groupinstall "Development Tools"
sudo yum install pkgconfig openssl-devel

# Arch Linux
sudo pacman -S base-devel pkg-config openssl
```

#### macOS
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Or install via Homebrew
brew install pkg-config openssl
```

#### BSD (FreeBSD/OpenBSD/NetBSD)
```bash
# FreeBSD
pkg install pkgconf

# OpenBSD
pkg_add pkgconf

# NetBSD
pkgin install pkgconf
```

### Optional Dependencies (Feature-Gated)

These are only required if building with specific features:

#### DNSSEC Support (feature: dnssec)
- **ring** crate (pure Rust, no external deps)
- Provides RSA, ECDSA, Ed25519 cryptography

#### D-Bus Integration (feature: dbus)
- **Linux:** `libdbus-1-dev` or `dbus-devel`
```bash
# Debian/Ubuntu
sudo apt-get install libdbus-1-dev

# Red Hat/Fedora
sudo yum install dbus-devel
```

#### Netfilter Conntrack (feature: conntrack)
- **Linux only:** `libnetfilter-conntrack-dev`
```bash
# Debian/Ubuntu
sudo apt-get install libnetfilter-conntrack-dev

# Red Hat/Fedora
sudo yum install libnetfilter_conntrack-devel
```

#### nftables Integration (feature: nftables)
- **Linux only:** `libnftables-dev`
```bash
# Debian/Ubuntu
sudo apt-get install libnftables-dev

# Red Hat/Fedora
sudo yum install libnftables-devel
```

#### Lua Scripting (feature: lua)
- **Lua 5.4** (mlua crate uses system Lua or vendored version)
```bash
# Debian/Ubuntu
sudo apt-get install liblua5.4-dev

# Red Hat/Fedora
sudo yum install lua-devel

# macOS
brew install lua
```

---

## Platform-Specific Instructions

### Linux (All Distributions)

Linux is the primary development platform with full feature support.

#### Debian/Ubuntu

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev

# Optional: Install all feature dependencies
sudo apt-get install libdbus-1-dev libnetfilter-conntrack-dev \
                     libnftables-dev liblua5.4-dev

# Build with all features
cargo build --release --features "dhcp dns tftp dnssec ipv6 dbus conntrack nftables"

# Install
sudo cargo install --path . --features default

# Verify installation
dnsmasq-rs --version
```

#### Red Hat/CentOS/Fedora

```bash
# Install dependencies
sudo yum groupinstall "Development Tools"
sudo yum install pkgconfig openssl-devel

# Optional: Install all feature dependencies
sudo yum install dbus-devel libnetfilter_conntrack-devel \
                 libnftables-devel lua-devel

# Build and install
cargo build --release --features default
sudo cargo install --path . --features default
```

#### Arch Linux

```bash
# Install dependencies
sudo pacman -S base-devel pkg-config openssl

# Optional: All feature dependencies
sudo pacman -S dbus libnetfilter_conntrack libnftables lua

# Build and install
cargo build --release --features default
sudo cargo install --path . --features default
```

#### Alpine Linux (For Docker)

Alpine is used for minimal Docker images:

```bash
# Install dependencies
apk add --no-cache build-base cargo rust pkgconf linux-headers musl-dev openssl-dev

# Build statically-linked binary
cargo build --release --target x86_64-unknown-linux-musl --features default

# Binary is fully static (no dynamic dependencies)
ldd target/x86_64-unknown-linux-musl/release/dnsmasq-rs
# Output: not a dynamic executable
```

### BSD (FreeBSD/OpenBSD/NetBSD)

#### FreeBSD

```bash
# Install Rust
pkg install rust cargo pkgconf

# Build
cargo build --release --features "dhcp dns tftp bpf"

# Install
cargo install --path . --features default
```

#### OpenBSD

```bash
# Install Rust
pkg_add rust cargo pkgconf

# Build
cargo build --release --features "dhcp dns tftp bpf"

# Install
cargo install --path . --features default
```

#### NetBSD

```bash
# Install Rust
pkgin install rust cargo pkgconf

# Build
cargo build --release --features "dhcp dns tftp bpf"

# Install
cargo install --path . --features default
```

### macOS

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install dependencies
brew install pkg-config openssl

# Build
cargo build --release --features "dhcp dns tftp"

# Install
cargo install --path . --features default

# Verify
dnsmasq-rs --version
```

### Solaris/illumos

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build with generic platform support
cargo build --release --features default

# Note: Limited platform-specific features on Solaris
# (no netlink, no BPF, uses generic POSIX networking)
```

---

## Feature Flags

The Rust implementation uses Cargo feature flags to mirror C's compile-time macros (Section 0.3.2).

### Default Features

```bash
# Build with defaults (DNS, DHCP, TFTP)
cargo build --release

# Equivalent to:
cargo build --release --features "dns dhcp tftp"
```

### Major Subsystem Features

| Feature | Description | C Equivalent |
|---------|-------------|--------------|
| `dns` | DNS forwarding and caching | Always enabled |
| `dhcp` | DHCPv4/v6 server | `HAVE_DHCP`, `HAVE_DHCP6` |
| `dhcp-v4` | DHCPv4 only | `HAVE_DHCP` |
| `dhcp-v6` | DHCPv6 only | `HAVE_DHCP6` |
| `tftp` | TFTP server | `HAVE_TFTP` |
| `dnssec` | DNSSEC validation | `HAVE_DNSSEC` |
| `auth-dns` | Authoritative DNS | `HAVE_AUTH` |

### IPv6 Features

| Feature | Description | C Equivalent |
|---------|-------------|--------------|
| `ipv6` | IPv6 support (DHCP v6, RA, SLAAC) | Always enabled |
| `radv` | Router Advertisement | `HAVE_DHCP6` |
| `slaac` | SLAAC support | `HAVE_DHCP6` |

### Platform Integration Features

| Feature | Description | Platform | C Equivalent |
|---------|-------------|----------|--------------|
| `netlink` | Linux netlink interface monitoring | Linux | `HAVE_LINUX_NETWORK` |
| `bpf` | BSD Packet Filter | BSD/macOS | `HAVE_BSD_NETWORK` |
| `inotify` | File monitoring (Linux) | Linux | `HAVE_INOTIFY` |
| `dbus` | D-Bus integration | Linux | `HAVE_DBUS` |
| `ubus` | OpenWrt ubus | OpenWrt | `HAVE_UBUS` |
| `conntrack` | Connection tracking | Linux | `HAVE_CONNTRACK` |
| `ipset` | ipset integration | Linux | `HAVE_IPSET` |
| `nftables` | nftables integration | Linux | `HAVE_NFTSET` |

### Build Examples

```bash
# Minimal build (DNS only)
cargo build --release --no-default-features --features dns

# Full-featured Linux build
cargo build --release --features "dns dhcp tftp dnssec ipv6 dbus netlink inotify conntrack nftables"

# BSD build
cargo build --release --features "dns dhcp tftp dnssec ipv6 bpf"

# macOS build
cargo build --release --features "dns dhcp tftp dnssec ipv6 bpf"

# OpenWrt build
cargo build --release --features "dns dhcp tftp ubus"
```

### Checking Available Features

```bash
# List all features
cargo metadata --format-version 1 | jq '.packages[] | select(.name == "dnsmasq-rs") | .features'

# Or view Cargo.toml
cat Cargo.toml | grep -A 50 "\[features\]"
```

---

## Build Profiles

### Development Profile (default)

Fast compilation, debug symbols, no optimizations:

```bash
cargo build
# Binary: target/debug/dnsmasq-rs
# Size: ~50 MB (with debug info)
```

### Release Profile (production)

Full optimizations, stripped symbols:

```bash
cargo build --release
# Binary: target/release/dnsmasq-rs
# Size: ~5-10 MB
# Optimizations: -O3, LTO, single codegen unit
```

### Custom Profiles

Edit `Cargo.toml` for custom optimization:

```toml
[profile.release-small]
inherits = "release"
opt-level = "z"  # Optimize for size
lto = true
codegen-units = 1
strip = true
```

Build with custom profile:
```bash
cargo build --profile release-small
```

---

## Cross-Compilation

### Linux → Linux (Different Architecture)

```bash
# Install target
rustup target add aarch64-unknown-linux-gnu

# Install cross-compilation toolchain
sudo apt-get install gcc-aarch64-linux-gnu

# Configure Cargo
cat >> ~/.cargo/config.toml << EOF
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
EOF

# Build
cargo build --release --target aarch64-unknown-linux-gnu
```

### Linux → musl (Static Binary)

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Install musl tools
sudo apt-get install musl-tools

# Build
cargo build --release --target x86_64-unknown-linux-musl

# Verify static
ldd target/x86_64-unknown-linux-musl/release/dnsmasq-rs
# Output: not a dynamic executable
```

### Using cross (Docker-based)

```bash
# Install cross
cargo install cross

# Build for any target
cross build --release --target aarch64-unknown-linux-gnu
cross build --release --target armv7-unknown-linux-gnueabihf
cross build --release --target x86_64-unknown-linux-musl
```

---

## Docker Builds

### Alpine Linux Base (Section 0.5.5)

The project supports Alpine Linux versions: 3.19.9, 3.20.8, 3.21.5, 3.22.2

#### Multi-Stage Dockerfile

```bash
# Build Docker image with default Alpine version (3.22.2)
docker build -f Dockerfile.rust -t dnsmasq-rs:latest .

# Build with specific Alpine version
docker build -f Dockerfile.rust -t dnsmasq-rs:alpine3.21.5 \
  --build-arg ALPINE_VERSION=3.21.5 .

# Run container
docker run -d --name dnsmasq-rs \
  -p 53:53/udp -p 53:53/tcp -p 67:67/udp \
  -v /etc/dnsmasq.conf:/etc/dnsmasq.conf:ro \
  dnsmasq-rs:latest
```

#### Docker Compose

```bash
# Build and run with Docker Compose
docker-compose -f docker-compose.rust.yml up -d

# View logs
docker-compose -f docker-compose.rust.yml logs -f

# Stop
docker-compose -f docker-compose.rust.yml down
```

#### Example Dockerfile.rust

```dockerfile
# Multi-stage build for minimal image size
ARG ALPINE_VERSION=3.22.2
FROM alpine:${ALPINE_VERSION} AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    cargo \
    rust \
    pkgconf \
    linux-headers \
    musl-dev \
    openssl-dev

# Set working directory
WORKDIR /build

# Copy source
COPY . .

# Build statically-linked binary
RUN cargo build --release --target x86_64-unknown-linux-musl --features default

# Final stage - minimal runtime image
FROM alpine:${ALPINE_VERSION}

# Install runtime dependencies (minimal)
RUN apk add --no-cache ca-certificates

# Copy binary from builder
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/dnsmasq-rs /usr/local/bin/

# Create non-root user
RUN addgroup -g 1000 dnsmasq && \
    adduser -D -u 1000 -G dnsmasq dnsmasq

# Expose ports
EXPOSE 53/udp 53/tcp 67/udp 547/udp 69/udp

# Run as non-root
USER dnsmasq

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD dnsmasq-rs --test || exit 1

# Entry point
ENTRYPOINT ["/usr/local/bin/dnsmasq-rs"]
CMD ["--no-daemon"]
```

---

## Static vs Dynamic Linking

### Dynamic Linking (Default)

```bash
# Standard build (dynamic linking)
cargo build --release

# Check dependencies
ldd target/release/dnsmasq-rs
# Output:
#   linux-vdso.so.1
#   libgcc_s.so.1
#   libpthread.so.0
#   libdl.so.2
#   libc.so.6
```

### Static Linking (musl)

```bash
# Build with musl target
cargo build --release --target x86_64-unknown-linux-musl

# Verify fully static
ldd target/x86_64-unknown-linux-musl/release/dnsmasq-rs
# Output: not a dynamic executable

# Advantages:
# - Single binary with no dependencies
# - Portable across Linux distributions
# - Ideal for Docker containers
```

### Partial Static Linking

```bash
# Link statically against most libraries
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release

# Check result
ldd target/release/dnsmasq-rs
```

---

## Troubleshooting

### Issue: Rust Version Mismatch

**Symptom:** `error: package requires rustc 1.91.0`

**Solution:**
```bash
# Update Rust to 1.91.0
rustup update stable
rustup default stable

# Verify
rustc --version
```

### Issue: Linker Errors

**Symptom:** `error: linking with 'cc' failed`

**Solution:**
```bash
# Install build essentials
sudo apt-get install build-essential

# Or for musl
sudo apt-get install musl-tools
```

### Issue: Missing OpenSSL

**Symptom:** `Could not find directory of OpenSSL installation`

**Solution:**
```bash
# Install OpenSSL development headers
sudo apt-get install libssl-dev pkg-config

# Or use vendored OpenSSL
cargo build --release --features vendored-openssl
```

### Issue: Feature Not Available

**Symptom:** `error: no matching package named 'zbus'`

**Solution:**
```bash
# Feature requires specific dependency
# Build without that feature or install dependency

# Example: D-Bus not available on macOS
cargo build --release --no-default-features --features "dns dhcp tftp"
```

### Issue: Out of Memory During Build

**Symptom:** `SIGKILL` or `Killed` during compilation

**Solution:**
```bash
# Reduce parallel jobs
cargo build --release -j 2

# Or increase swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Issue: Slow Compilation

**Solution:**
```bash
# Use incremental compilation (dev builds)
export CARGO_INCREMENTAL=1

# Use sccache for caching
cargo install sccache
export RUSTC_WRAPPER=sccache

# Use faster linker (mold)
sudo apt-get install mold
export RUSTFLAGS="-C link-arg=-fuse-ld=mold"
```

### Issue: Permission Denied on Port Binding

**Symptom:** `Permission denied (os error 13)` when binding to port 53 or 67

**Solution:**
```bash
# Option 1: Run as root (not recommended for production)
sudo ./target/release/dnsmasq-rs

# Option 2: Grant CAP_NET_BIND_SERVICE capability
sudo setcap 'cap_net_bind_service=+ep' ./target/release/dnsmasq-rs

# Option 3: Use systemd socket activation
# (see tools/systemd/dnsmasq-rs.service)
```

### Issue: DNS Query Timeouts

**Symptom:** DNS queries timing out or slow responses

**Solution:**
```bash
# Check firewall rules
sudo iptables -L -n | grep 53

# Verify UDP port 53 is open
sudo ss -ulnp | grep 53

# Test DNS resolution
dig @localhost example.com

# Check logs
journalctl -u dnsmasq-rs -f
```

### Issue: DHCP Lease File Corruption

**Symptom:** `Error reading lease file`

**Solution:**
```bash
# Backup and remove corrupted lease file
sudo cp /var/lib/misc/dnsmasq.leases /var/lib/misc/dnsmasq.leases.bak
sudo rm /var/lib/misc/dnsmasq.leases

# Restart dnsmasq-rs (will create new lease file)
sudo systemctl restart dnsmasq-rs

# Verify
sudo journalctl -u dnsmasq-rs -n 50
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Build and Test

on: [push, pull_request]

jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        rust: [1.91.0]
    
    runs-on: ${{ matrix.os }}
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: ${{ matrix.rust }}
          override: true
          components: rustfmt, clippy
      
      - name: Cache cargo registry
        uses: actions/cache@v3
        with:
          path: ~/.cargo/registry
          key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}
      
      - name: Cache cargo index
        uses: actions/cache@v3
        with:
          path: ~/.cargo/git
          key: ${{ runner.os }}-cargo-index-${{ hashFiles('**/Cargo.lock') }}
      
      - name: Cache target directory
        uses: actions/cache@v3
        with:
          path: target
          key: ${{ runner.os }}-target-${{ hashFiles('**/Cargo.lock') }}
      
      - name: Check formatting
        run: cargo fmt -- --check
      
      - name: Clippy
        run: cargo clippy --all-features -- -D warnings
      
      - name: Build
        run: cargo build --release --all-features
      
      - name: Test
        run: cargo test --all-features
      
      - name: Upload binary
        uses: actions/upload-artifact@v3
        with:
          name: dnsmasq-rs-${{ matrix.os }}
          path: target/release/dnsmasq-rs
```

### GitLab CI

```yaml
stages:
  - lint
  - build
  - test
  - deploy

variables:
  CARGO_HOME: $CI_PROJECT_DIR/.cargo

cache:
  paths:
    - .cargo/
    - target/

lint:
  stage: lint
  image: rust:1.91.0
  script:
    - rustc --version
    - cargo --version
    - cargo fmt -- --check
    - cargo clippy --all-features -- -D warnings

build:
  stage: build
  image: rust:1.91.0
  script:
    - cargo build --release --all-features
  artifacts:
    paths:
      - target/release/dnsmasq-rs
    expire_in: 1 week

test:
  stage: test
  image: rust:1.91.0
  script:
    - cargo test --all-features

deploy:docker:
  stage: deploy
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -f Dockerfile.rust -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
  only:
    - main
```

### Travis CI

```yaml
language: rust
rust:
  - 1.91.0

os:
  - linux
  - osx

cache: cargo

before_install:
  - if [ "$TRAVIS_OS_NAME" = "linux" ]; then sudo apt-get update; fi
  - if [ "$TRAVIS_OS_NAME" = "linux" ]; then sudo apt-get install -y libdbus-1-dev; fi

script:
  - cargo fmt -- --check
  - cargo clippy --all-features -- -D warnings
  - cargo build --release --all-features
  - cargo test --all-features

deploy:
  provider: releases
  api_key: $GITHUB_TOKEN
  file: target/release/dnsmasq-rs
  skip_cleanup: true
  on:
    tags: true
```

---

## Build Performance Tips

1. **Use incremental compilation:** `export CARGO_INCREMENTAL=1`
2. **Cache dependencies:** Use sccache or CI caching
3. **Parallel builds:** `cargo build -j $(nproc)`
4. **Faster linker:** Use mold or lld
   ```bash
   # Install mold
   sudo apt-get install mold
   
   # Configure in .cargo/config.toml
   [target.x86_64-unknown-linux-gnu]
   linker = "clang"
   rustflags = ["-C", "link-arg=-fuse-ld=mold"]
   ```
5. **Reduce features:** Only enable needed features
   ```bash
   cargo build --release --no-default-features --features "dns dhcp"
   ```
6. **Use cargo-nextest:** Faster test runner
   ```bash
   cargo install cargo-nextest
   cargo nextest run
   ```

---

## Binary Size Optimization

### Minimal Binary Size

```bash
# Use release profile with size optimization
cargo build --profile release-small

# Or set environment variables
RUSTFLAGS="-C opt-level=z -C lto=fat -C codegen-units=1 -C strip=symbols" \
  cargo build --release --no-default-features --features dns
```

### Strip Symbols

```bash
# Strip after build
strip target/release/dnsmasq-rs

# Or use strip in Cargo.toml
[profile.release]
strip = true
```

### Check Binary Size

```bash
# Check size
ls -lh target/release/dnsmasq-rs

# Analyze binary sections
size target/release/dnsmasq-rs

# Detailed analysis
cargo bloat --release
```

---

## Security Considerations

### Capability-Based Privilege Management

```bash
# Grant only necessary capabilities (Linux)
sudo setcap 'cap_net_bind_service,cap_net_admin=+ep' target/release/dnsmasq-rs

# Verify capabilities
getcap target/release/dnsmasq-rs
```

### Running as Non-Root User

```bash
# Create dedicated user
sudo useradd -r -s /usr/sbin/nologin -M dnsmasq

# Set ownership
sudo chown dnsmasq:dnsmasq /var/lib/misc/dnsmasq.leases

# Run as dnsmasq user (after binding privileged ports)
# (This is handled automatically by the daemon - see Section 0.7.5)
```

### AppArmor/SELinux Integration

```bash
# Example AppArmor profile location
sudo vi /etc/apparmor.d/usr.local.bin.dnsmasq-rs

# Load profile
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.dnsmasq-rs
```

---

## Benchmarking

### Build Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench dns_cache

# Generate detailed reports
cargo bench -- --save-baseline main
```

### Performance Profiling

```bash
# Install perf tools (Linux)
sudo apt-get install linux-tools-common linux-tools-generic

# Profile DNS queries
cargo build --release
sudo perf record -g ./target/release/dnsmasq-rs --no-daemon

# Generate report
sudo perf report
```

---

## Related Documentation

- [Architecture](ARCHITECTURE.md) - System design and components
- [Testing](TESTING.md) - Testing strategy and benchmarks
- [Contributing](CONTRIBUTING.md) - Development guidelines
- [Migration](MIGRATION.md) - Migrating from C version

---

**For most users, `cargo build --release` is sufficient. For production deployments, consider Docker builds on Alpine Linux for minimal, secure containers.**
