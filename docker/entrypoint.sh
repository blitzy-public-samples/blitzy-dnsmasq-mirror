#!/bin/sh
# Docker entrypoint script for dnsmasq (Rust/C implementation)
# Handles container initialization, configuration validation, signal forwarding,
# and proper process management for containerized deployment
#
# This script ensures:
# - Proper signal handling (SIGTERM for shutdown, SIGHUP for reload)
# - Configuration validation before startup
# - Environment variable processing for runtime configuration
# - PID 1 process management via exec
# - Graceful fallback between Rust and C binaries

set -e  # Exit on error

# Color codes for logging (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Logging functions
log_info() {
    echo "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*"
}

log_success() {
    echo "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*"
}

log_warn() {
    echo "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" >&2
}

log_error() {
    echo "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" >&2
}

# Container startup banner
echo ""
echo "=========================================="
echo "  dnsmasq Container Starting"
echo "  Time: $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "=========================================="
echo ""

# ============================================================================
# 1. CONTAINER INITIALIZATION
# ============================================================================

log_info "Starting container initialization..."

# Create necessary runtime directories
log_info "Creating runtime directories..."
mkdir -p /var/run/dnsmasq
mkdir -p /var/lib/misc
mkdir -p /var/log

# Set appropriate permissions for nobody user
# dnsmasq typically runs as nobody:nogroup for security
log_info "Setting directory permissions..."
chown -R nobody:nogroup /var/run/dnsmasq 2>/dev/null || true
chown -R nobody:nogroup /var/lib/misc 2>/dev/null || true

log_success "Runtime directories created and configured"

# ============================================================================
# 2. BINARY DETECTION (Rust vs C)
# ============================================================================

log_info "Detecting dnsmasq binary..."

DNSMASQ_BIN=""
BINARY_TYPE=""

# Search paths in order of preference
SEARCH_PATHS="/usr/local/bin/dnsmasq /usr/sbin/dnsmasq /usr/bin/dnsmasq /target/release/dnsmasq"

for candidate in $SEARCH_PATHS; do
    if [ -x "$candidate" ]; then
        DNSMASQ_BIN="$candidate"
        break
    fi
done

if [ -z "$DNSMASQ_BIN" ]; then
    log_error "No dnsmasq binary found in search paths"
    log_error "Searched: $SEARCH_PATHS"
    exit 1
fi

# Determine binary type (Rust vs C)
# Rust binaries typically contain rustc metadata or specific strings
if strings "$DNSMASQ_BIN" 2>/dev/null | grep -q "rustc\|cargo\|tokio" 2>/dev/null; then
    BINARY_TYPE="Rust"
elif strings "$DNSMASQ_BIN" 2>/dev/null | grep -q "Simon Kelley\|dnsmasq" 2>/dev/null; then
    BINARY_TYPE="C"
else
    BINARY_TYPE="Unknown"
fi

log_success "Found dnsmasq binary: $DNSMASQ_BIN"
log_info "Binary type: $BINARY_TYPE"

# Verify binary is executable
if [ ! -x "$DNSMASQ_BIN" ]; then
    log_error "Binary $DNSMASQ_BIN exists but is not executable"
    exit 1
fi

# ============================================================================
# 3. ENVIRONMENT VARIABLE PROCESSING
# ============================================================================

log_info "Processing environment variables..."

# UPSTREAM_DNS: Comma-separated list of upstream DNS servers
# Default: Google Public DNS (8.8.8.8, 8.8.4.4)
UPSTREAM_DNS="${UPSTREAM_DNS:-8.8.8.8,8.8.4.4}"
log_info "Upstream DNS servers: $UPSTREAM_DNS"

# LOG_QUERIES: Enable query logging (true/false)
LOG_QUERIES="${LOG_QUERIES:-false}"
log_info "Query logging: $LOG_QUERIES"

# CACHE_SIZE: DNS cache size (number of entries)
CACHE_SIZE="${CACHE_SIZE:-150}"
log_info "Cache size: $CACHE_SIZE"

# DNSMASQ_OPTS: Additional command-line options
DNSMASQ_OPTS="${DNSMASQ_OPTS:-}"
if [ -n "$DNSMASQ_OPTS" ]; then
    log_info "Additional options: $DNSMASQ_OPTS"
fi

# Build command-line arguments from environment variables
CMD_ARGS=""

# Add upstream DNS servers
IFS=',' read -r -a dns_servers <<EOF
$UPSTREAM_DNS
EOF

for server in ${dns_servers[@]}; do
    # Trim whitespace
    server=$(echo "$server" | xargs)
    if [ -n "$server" ]; then
        CMD_ARGS="$CMD_ARGS --server=$server"
    fi
done

# Add cache size
CMD_ARGS="$CMD_ARGS --cache-size=$CACHE_SIZE"

# Add query logging if enabled
if [ "$LOG_QUERIES" = "true" ] || [ "$LOG_QUERIES" = "1" ] || [ "$LOG_QUERIES" = "yes" ]; then
    CMD_ARGS="$CMD_ARGS --log-queries"
    log_info "Query logging enabled"
fi

# Add foreground flag (required for Docker)
CMD_ARGS="$CMD_ARGS --keep-in-foreground"

# Disable DNS rebind protection for common private networks (Docker networks)
CMD_ARGS="$CMD_ARGS --rebind-localhost-ok"

# Add user-specified additional options
if [ -n "$DNSMASQ_OPTS" ]; then
    CMD_ARGS="$CMD_ARGS $DNSMASQ_OPTS"
fi

log_success "Command-line arguments prepared"

# ============================================================================
# 4. CONFIGURATION FILE HANDLING
# ============================================================================

CONFIG_FILE="${CONFIG_FILE:-/etc/dnsmasq.conf}"

log_info "Checking configuration file: $CONFIG_FILE"

# Check if configuration file exists
if [ -f "$CONFIG_FILE" ]; then
    log_success "Configuration file found: $CONFIG_FILE"
    CMD_ARGS="$CMD_ARGS --conf-file=$CONFIG_FILE"
    
    # Display configuration file summary (first 20 non-comment lines)
    log_info "Configuration summary:"
    grep -v '^#' "$CONFIG_FILE" | grep -v '^$' | head -n 20 | while read -r line; do
        echo "  $line"
    done
else
    log_warn "Configuration file not found: $CONFIG_FILE"
    log_warn "Starting with command-line configuration only"
    CMD_ARGS="$CMD_ARGS --conf-file=/dev/null"
fi

# ============================================================================
# 5. CONFIGURATION VALIDATION
# ============================================================================

log_info "Validating dnsmasq configuration..."

# Run configuration test
# Use --test flag if available, otherwise just check syntax
if "$DNSMASQ_BIN" --test $CMD_ARGS >/tmp/dnsmasq-test.log 2>&1; then
    log_success "Configuration validation passed"
    
    # Show validation output if verbose
    if [ "${VERBOSE:-false}" = "true" ]; then
        cat /tmp/dnsmasq-test.log
    fi
else
    log_error "Configuration validation failed!"
    log_error "Error details:"
    cat /tmp/dnsmasq-test.log
    echo ""
    log_error "Common issues:"
    log_error "  - Invalid option syntax in $CONFIG_FILE"
    log_error "  - Conflicting options"
    log_error "  - Missing referenced files"
    log_error "  - Invalid network interface names"
    exit 1
fi

rm -f /tmp/dnsmasq-test.log

# ============================================================================
# 6. SIGNAL HANDLING SETUP
# ============================================================================

log_info "Setting up signal handlers..."

# Signal handling for graceful shutdown and reload
# SIGTERM: Graceful shutdown (sent by docker stop)
# SIGHUP: Configuration reload
# SIGINT: Graceful shutdown (Ctrl+C)

# Note: When using exec, signals are passed directly to the child process
# dnsmasq handles SIGTERM and SIGHUP internally, so we don't need traps
# This is the correct approach for PID 1 process management

log_success "Signal handling configured (native dnsmasq handling via exec)"

# ============================================================================
# 7. PRE-FLIGHT CHECKS
# ============================================================================

log_info "Running pre-flight checks..."

# Check if we can bind to port 53 (DNS)
if [ "${SKIP_PORT_CHECK:-false}" != "true" ]; then
    # Try to check port availability (may not work in all container environments)
    if command -v netstat >/dev/null 2>&1; then
        if netstat -tuln 2>/dev/null | grep -q ':53 '; then
            log_warn "Port 53 appears to be in use"
            log_warn "This may cause startup failure if not intentional"
        fi
    fi
fi

# Check available memory
if [ -f /proc/meminfo ]; then
    AVAILABLE_MEM=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    if [ -n "$AVAILABLE_MEM" ]; then
        AVAILABLE_MB=$((AVAILABLE_MEM / 1024))
        log_info "Available memory: ${AVAILABLE_MB} MB"
        
        if [ "$AVAILABLE_MB" -lt 50 ]; then
            log_warn "Low memory available (< 50 MB)"
            log_warn "Consider reducing cache size or increasing container memory"
        fi
    fi
fi

log_success "Pre-flight checks completed"

# ============================================================================
# 8. FINAL STARTUP
# ============================================================================

echo ""
echo "=========================================="
echo "  Starting dnsmasq daemon"
echo "=========================================="
log_info "Binary: $DNSMASQ_BIN ($BINARY_TYPE)"
log_info "Configuration: $CONFIG_FILE"
log_info "Command: $DNSMASQ_BIN $CMD_ARGS"
echo ""

# Additional startup information
log_info "Container will respond to signals:"
log_info "  - SIGTERM: Graceful shutdown"
log_info "  - SIGHUP: Configuration reload"
log_info "  - SIGINT: Graceful shutdown"
echo ""

# Execute dnsmasq with exec to replace shell process
# This ensures dnsmasq runs as PID 1 and receives signals directly
# This is critical for proper Docker container lifecycle management
exec "$DNSMASQ_BIN" $CMD_ARGS
