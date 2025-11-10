# Out-of-Scope Issues Documentation

## Architectural Inconsistency: RwLock Type Mismatch

### Issue Description
There is an architectural inconsistency between DHCPv4 and DHCPv6 server implementations regarding the type of RwLock used for daemon state management:

- **DHCPv4Server** (`src/dhcp/v4/server.rs`): Uses `std::sync::RwLock<DaemonState>`
- **DHCPv6Server** (`src/dhcp/v6/server.rs`): Uses `tokio::sync::RwLock<DaemonState>`
- **Main Application** (`src/main.rs`): Uses `tokio::sync::RwLock<DaemonState>`

### Impact
1. Cannot use both DHCPv4 and DHCPv6 servers with the same daemon state instance
2. Requires creating separate daemon state instances with different RwLock types
3. Inconsistent with the main application's choice of `tokio::sync::RwLock`

### Root Cause
DHCPv4Server uses synchronous `.read().unwrap()` calls which require `std::sync::RwLock`, while DHCPv6Server is fully async and uses `.read().await` which requires `tokio::sync::RwLock`.

### Workaround Applied in Example
In `examples/dhcp_server.rs`, created two separate daemon state instances:
- One with `std::sync::RwLock` for DHCPv4Server
- One with `tokio::sync::RwLock` for DHCPv6Server (cloning the config)

### Recommendation for Future Work
Consider migrating DHCPv4Server to use async/await patterns consistently with DHCPv6Server and the main application, allowing both to share `tokio::sync::RwLock<DaemonState>`.

### Files Affected (Out-of-Scope)
- `src/dhcp/v4/server.rs` - Would need refactoring to use tokio::sync::RwLock
- All call sites of DHCPv4Server that would need to be updated

### Validation Status
- **In-Scope File Status**: `examples/dhcp_server.rs` - FIXED with workaround
- **Out-of-Scope Files**: Documented only, not modified per scope constraints
