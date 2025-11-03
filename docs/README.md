# dnsmasq Developer Documentation

## Overview

**dnsmasq** is a lightweight DNS forwarder and DHCP/DHCPv6 server designed for small networks and embedded systems. This documentation provides comprehensive technical reference for developers who need to understand, modify, or extend the dnsmasq implementation.

This developer documentation covers:
- System architecture and design patterns
- Protocol implementations (DNS, DHCPv4, DHCPv6, DNSSEC, TFTP)
- API reference for all functions and data structures
- Build system and configuration options
- Platform-specific implementation details

## Documentation Structure

The dnsmasq documentation is organized into two complementary layers:

### Inline Documentation
**Location:** `src/` directory - embedded within C source files  
**Format:** Doxygen-compatible comments (`/** ... */`)  
**Purpose:** API reference and function-level implementation details  
**Coverage:** 
- File-level documentation for all 51 source files (43 `.c` + 8 `.h`)
- Function documentation for 420-600 functions
- Struct documentation for 50+ data structures
- Macro documentation for 90+ configuration options

**How to Access:** Generate HTML documentation by running `doxygen Doxyfile` (see below)

### Standalone Documentation
**Location:** `docs/` directory (this location)  
**Format:** Markdown files (`.md`)  
**Purpose:** Architecture guides, protocol implementation documentation, and cross-cutting concerns  
**Coverage:** System design, protocol compliance (RFC mappings), build instructions, configuration system

## Getting Started

### Prerequisites
To effectively use this documentation, you should have:
- **Basic understanding of C programming** - dnsmasq is written in C99
- **Familiarity with DNS and DHCP protocols** - knowledge of RFC 1035, RFC 2131, RFC 3315
- **Knowledge of Unix/Linux system programming** - sockets, signals, event loops, process management
- **Understanding of network services** - TCP/IP stack, packet processing, protocol state machines

### How to Read This Documentation

**For new developers:**
1. Start with [ARCHITECTURE.md](ARCHITECTURE.md) for system overview and component interactions
2. Read protocol-specific documentation for your area of interest
3. Refer to inline API documentation (generated HTML) for implementation details
4. Use [BUILDING.md](BUILDING.md) and [CONFIGURATION.md](CONFIGURATION.md) for practical setup

**For specific tasks:**
- **Understanding DNS forwarding:** [DNS_FORWARDING.md](DNS_FORWARDING.md) + `forward.c` inline docs
- **Understanding caching:** [DNS_CACHING.md](DNS_CACHING.md) + `cache.c` inline docs
- **Modifying DHCP:** [DHCP_V4.md](DHCP_V4.md) or [DHCP_V6.md](DHCP_V6.md) + `dhcp.c`/`dhcp6.c` inline docs
- **Adding DNSSEC features:** [DNSSEC.md](DNSSEC.md) + `dnssec.c` inline docs
- **Porting to new platform:** [BUILDING.md](BUILDING.md) + `network.c`/`netlink.c`/`bpf.c` inline docs

## Documentation Files Index

### Architecture and System Design
- **[ARCHITECTURE.md](ARCHITECTURE.md)** (2500+ words)  
  System architecture and design patterns. Covers single-process event-driven architecture, component interactions, data flow diagrams, memory management strategy, platform abstraction layer, and inter-module dependencies.

### DNS Implementation
- **[DNS_FORWARDING.md](DNS_FORWARDING.md)** (1500+ words)  
  DNS query forwarding implementation. Covers query processing pipeline, upstream server selection algorithm, retry and timeout logic, EDNS0 extension handling, cache poisoning prevention, and RFC 1035 compliance.

- **[DNS_CACHING.md](DNS_CACHING.md)** (1500+ words)  
  DNS caching algorithm and implementation. Covers hash table structure, LRU eviction policy, negative caching (NXDOMAIN/NODATA), TTL management, CNAME chain resolution, and cache-DHCP integration.

### DHCP Implementation
- **[DHCP_V4.md](DHCP_V4.md)** (2000+ words)  
  DHCPv4 server implementation per RFC 2131. Covers state machine, lease allocation algorithm, address pool management, lease database persistence, DHCP option handling, PXE/network boot integration, and ping-before-offer conflict detection.

- **[DHCP_V6.md](DHCP_V6.md)** (2000+ words)  
  DHCPv6 server implementation per RFC 3315. Covers DHCPv6 state machine, architectural differences from DHCPv4, DUID handling, IA_NA/IA_TA address assignment, Router Advertisement integration (RFC 4861), and SLAAC (RFC 4862).

### Security and Validation
- **[DNSSEC.md](DNSSEC.md)** (1500+ words)  
  DNSSEC validation implementation per RFCs 4033/4034/4035. Covers supported cryptographic algorithms (RSA, ECDSA, Ed25519), trust anchor management, validation process flow, DS record chain of trust, NSEC/NSEC3 proof validation, and libnettle integration.

### Additional Services
- **[TFTP.md](TFTP.md)** (1000+ words)  
  TFTP server implementation per RFC 1350. Covers protocol compliance, PXE boot integration, OACK/blksize extension, concurrent transfer management, transfer state machine, and error handling.

### Configuration and Build
- **[CONFIGURATION.md](CONFIGURATION.md)** (1500+ words)  
  Configuration system documentation. Covers configuration file syntax, command-line vs file precedence, parsing algorithm, multi-level include system, dynamic reload semantics (SIGHUP), compile-time options matrix (all HAVE_* and NO_* macros), and option validation.

- **[BUILDING.md](BUILDING.md)** (1000+ words)  
  Build instructions and platform-specific compilation. Covers Linux, BSD, Android, macOS, and Solaris build procedures, dependency matrix with version requirements, COPTS feature selection examples, cross-compilation procedures, and troubleshooting.

## Generating API Documentation

To generate complete HTML API reference documentation from inline Doxygen comments:

### Command
```bash
doxygen Doxyfile
```

### Requirements
- **Doxygen 1.8.13+** - Install with: `apt-get install doxygen` (Debian/Ubuntu) or `yum install doxygen` (Red Hat/CentOS)
- **Web browser** - For viewing generated HTML

### Output
- **Location:** `docs/html/` directory
- **Entry point:** `docs/html/index.html`
- **Content:** Complete API reference with function documentation, struct documentation, file documentation, source code browser, and cross-references

### Viewing
```bash
# Open in default browser
open docs/html/index.html           # macOS
xdg-open docs/html/index.html       # Linux
start docs/html/index.html          # Windows

# Or use local web server
cd docs/html
python3 -m http.server 8000
# Navigate to http://localhost:8000
```

### Duration
Generating documentation for the complete dnsmasq codebase takes approximately 30-60 seconds.

## Source Code Organization

### Source Directory Structure
All C implementation code resides in the `src/` directory:
- **43 C source files** (`.c`) - Implementation
- **8 header files** (`.h`) - Type definitions and declarations

### Core Modules

#### Main Daemon
- `dnsmasq.c` - Main entry point, event loop orchestration, signal handling
- `poll.c` - Poll wrapper for event-driven architecture
- `dnsmasq.h` - Primary type definitions (50+ structs)

#### DNS Subsystem
- `forward.c` - DNS query forwarding and upstream server management
- `cache.c` - DNS caching with LRU eviction
- `rfc1035.c` - DNS packet format per RFC 1035
- `dnssec.c` - DNSSEC validation per RFCs 4033-4035
- `auth.c` - Authoritative DNS server

#### DHCP Subsystem
- `dhcp.c` - DHCPv4 server core logic
- `dhcp6.c` - DHCPv6 server core logic
- `rfc2131.c` - DHCPv4 protocol implementation (RFC 2131)
- `rfc3315.c` - DHCPv6 protocol implementation (RFC 3315)
- `lease.c` - Lease database persistence
- `radv.c` - IPv6 Router Advertisement (RFC 4861)

#### Network Layer
- `network.c` - Socket management, interface enumeration
- `netlink.c` - Linux Netlink interface monitoring
- `bpf.c` - BSD Berkeley Packet Filter interface enumeration

#### Configuration
- `option.c` - Configuration file and command-line parser (5794 lines)
- `config.h` - Compile-time configuration constants and feature gates

#### Supporting Modules
- `util.c` - Utility functions (SURF RNG, canonicalization)
- `blockdata.c` - Block-chained buffers for variable-length data
- `log.c` - Asynchronous queued logging
- `helper.c` - External script execution with privilege separation
- `crypto.c` - Cryptographic primitive wrappers (libnettle)

#### Integration Modules
- `dbus.c` - D-Bus control interface
- `ubus.c` - OpenWrt ubus control interface
- `tftp.c` - TFTP server (RFC 1350)
- `ipset.c` - Linux ipset integration
- `nftset.c` - nftables set integration

### Key Header Files
- `dnsmasq.h` - Primary type definitions (struct daemon, server, frec, crec, dhcp_lease, etc.)
- `config.h` - Compile-time configuration (HAVE_DHCP, HAVE_DNSSEC, tuning constants)
- `dhcp-protocol.h` - DHCPv4 packet structures
- `dhcp6-protocol.h` - DHCPv6 packet structures
- `dns-protocol.h` - DNS packet structures
- `radv-protocol.h` - Router Advertisement packet structures

## Contributing

This documentation is comprehensive and up-to-date as of its creation, covering:
- Complete dnsmasq architecture and component interactions
- Detailed protocol implementation documentation with RFC compliance
- API reference for all functions and data structures
- Build and configuration guidance for multiple platforms

For contributing to the dnsmasq project itself (code, bug reports, feature requests), please refer to the main project repository and Simon Kelley's contribution guidelines.

---

## Related Documentation

- [System Architecture](ARCHITECTURE.md)
- [DNS Forwarding](DNS_FORWARDING.md)
- [DNS Caching](DNS_CACHING.md)
- [DHCPv4 Server](DHCP_V4.md)
- [DHCPv6 Server](DHCP_V6.md)
- [DNSSEC Validation](DNSSEC.md)
- [TFTP Server](TFTP.md)
- [Configuration System](CONFIGURATION.md)
- [Building dnsmasq](BUILDING.md)

---

**Documentation Version:** Initial comprehensive documentation  
**dnsmasq Version:** All versions with source in `src/` directory  
**Last Updated:** Documentation creation date
