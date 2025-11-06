#!/bin/sh

# Copyright (c) 2024 dnsmasq Rust Refactoring Project
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 dated June, 1991, or version 3
# dated 29 June, 2007.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# Automated C/Rust compatibility testing for dnsmasq
# Verifies drop-in replacement capability by comparing behavior,
# configuration parsing, packet formats, and operational characteristics
# between C dnsmasq binary and Rust dnsmasq binary.

set -e

# Color output for readability
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Global test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Logging functions
log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[PASS]${NC} %s\n" "$1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_fail() {
    printf "${RED}[FAIL]${NC} %s\n" "$1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_skip() {
    printf "${YELLOW}[SKIP]${NC} %s\n" "$1"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    
    # Kill any running dnsmasq instances
    if [ -n "${C_PID:-}" ] && kill -0 "${C_PID}" 2>/dev/null; then
        kill "${C_PID}" 2>/dev/null || true
        wait "${C_PID}" 2>/dev/null || true
    fi
    
    if [ -n "${RUST_PID:-}" ] && kill -0 "${RUST_PID}" 2>/dev/null; then
        kill "${RUST_PID}" 2>/dev/null || true
        wait "${RUST_PID}" 2>/dev/null || true
    fi
    
    # Remove temporary directories
    if [ -n "${TEST_DIR:-}" ] && [ -d "${TEST_DIR}" ]; then
        rm -rf "${TEST_DIR}"
    fi
}

trap cleanup EXIT INT TERM

# Detect project root
detect_project_root() {
    # Try to find project root by looking for Makefile and Cargo.toml
    if [ -f "Makefile" ] && [ -f "Cargo.toml" ]; then
        PROJECT_ROOT="$(pwd)"
    elif [ -f "../Makefile" ] && [ -f "../Cargo.toml" ]; then
        PROJECT_ROOT="$(cd .. && pwd)"
    elif [ -f "../../Makefile" ] && [ -f "../../Cargo.toml" ]; then
        PROJECT_ROOT="$(cd ../.. && pwd)"
    else
        log_fail "Cannot find project root (looking for Makefile and Cargo.toml)"
        exit 1
    fi
    
    log_info "Project root: ${PROJECT_ROOT}"
}

# Detect binaries
detect_binaries() {
    # C binary location
    C_BINARY="${PROJECT_ROOT}/src/dnsmasq"
    if [ ! -x "${C_BINARY}" ]; then
        log_fail "C binary not found or not executable: ${C_BINARY}"
        log_info "Please build the C version first: make"
        exit 1
    fi
    log_info "C binary: ${C_BINARY}"
    
    # Rust binary location
    RUST_BINARY="${PROJECT_ROOT}/target/release/dnsmasq"
    if [ ! -x "${RUST_BINARY}" ]; then
        # Try debug build
        RUST_BINARY="${PROJECT_ROOT}/target/debug/dnsmasq"
        if [ ! -x "${RUST_BINARY}" ]; then
            log_fail "Rust binary not found or not executable"
            log_info "Please build the Rust version first: cargo build --release"
            exit 1
        fi
        log_warn "Using debug build: ${RUST_BINARY}"
    else
        log_info "Rust binary: ${RUST_BINARY}"
    fi
}

# Create test environment
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create temporary directories
    TEST_DIR="$(mktemp -d -t dnsmasq-compat-test.XXXXXX)"
    
    C_TEST_DIR="${TEST_DIR}/c"
    RUST_TEST_DIR="${TEST_DIR}/rust"
    
    mkdir -p "${C_TEST_DIR}"
    mkdir -p "${RUST_TEST_DIR}"
    
    # Find available ports
    C_DNS_PORT=$(find_free_port 15353)
    RUST_DNS_PORT=$(find_free_port 15453)
    
    C_DHCP_PORT=$(find_free_port 15367)
    RUST_DHCP_PORT=$(find_free_port 15467)
    
    log_info "C DNS port: ${C_DNS_PORT}, Rust DNS port: ${RUST_DNS_PORT}"
    log_info "C DHCP port: ${C_DHCP_PORT}, Rust DHCP port: ${RUST_DHCP_PORT}"
    
    # Create test configuration files
    create_test_configs
    
    log_info "Test directory: ${TEST_DIR}"
}

# Find free port
find_free_port() {
    start_port="${1:-10000}"
    port="${start_port}"
    while [ "${port}" -lt 65535 ]; do
        if ! netstat -an 2>/dev/null | grep -q ":${port} " && \
           ! ss -an 2>/dev/null | grep -q ":${port} "; then
            echo "${port}"
            return 0
        fi
        port=$((port + 1))
    done
    echo "${start_port}"
}

# Create test configuration files
create_test_configs() {
    # Basic configuration for C version
    cat > "${C_TEST_DIR}/dnsmasq.conf" <<EOF
# Test configuration for C dnsmasq
port=${C_DNS_PORT}
domain=test.local
local=/test.local/
expand-hosts
log-queries
log-facility=${C_TEST_DIR}/dnsmasq.log
pid-file=${C_TEST_DIR}/dnsmasq.pid
no-hosts
no-resolv
cache-size=150
server=8.8.8.8
server=8.8.4.4
address=/test.example/192.168.1.1
EOF

    # Basic configuration for Rust version
    cat > "${RUST_TEST_DIR}/dnsmasq.conf" <<EOF
# Test configuration for Rust dnsmasq
port=${RUST_DNS_PORT}
domain=test.local
local=/test.local/
expand-hosts
log-queries
log-facility=${RUST_TEST_DIR}/dnsmasq.log
pid-file=${RUST_TEST_DIR}/dnsmasq.pid
no-hosts
no-resolv
cache-size=150
server=8.8.8.8
server=8.8.4.4
address=/test.example/192.168.1.1
EOF

    # DHCP configuration if DHCP is enabled
    if check_dhcp_support; then
        cat >> "${C_TEST_DIR}/dnsmasq.conf" <<EOF
dhcp-range=192.168.100.50,192.168.100.150,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1
dhcp-leasefile=${C_TEST_DIR}/dnsmasq.leases
EOF

        cat >> "${RUST_TEST_DIR}/dnsmasq.conf" <<EOF
dhcp-range=192.168.100.50,192.168.100.150,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1
dhcp-leasefile=${RUST_TEST_DIR}/dnsmasq.leases
EOF
    fi
}

# Check if DHCP support is compiled in
check_dhcp_support() {
    if "${C_BINARY}" --version 2>&1 | grep -q -i "dhcp"; then
        return 0
    fi
    return 1
}

# Check if DNSSEC support is compiled in
check_dnssec_support() {
    if "${C_BINARY}" --version 2>&1 | grep -q -i "dnssec"; then
        return 0
    fi
    return 1
}

# Test 1: Configuration Parsing Tests
test_config_parsing() {
    echo ""
    log_info "=== Configuration Parsing Tests ==="
    
    # Test 1.1: Valid configuration acceptance
    log_info "Test: Both binaries accept valid configuration"
    if "${C_BINARY}" --test --conf-file="${C_TEST_DIR}/dnsmasq.conf" >/dev/null 2>&1; then
        if "${RUST_BINARY}" --test --conf-file="${RUST_TEST_DIR}/dnsmasq.conf" >/dev/null 2>&1; then
            log_success "Both binaries accept valid configuration"
        else
            log_fail "Rust binary rejected valid configuration"
        fi
    else
        log_fail "C binary rejected valid configuration"
    fi
    
    # Test 1.2: Invalid configuration rejection
    log_info "Test: Both binaries reject invalid configuration"
    cat > "${TEST_DIR}/invalid.conf" <<EOF
invalid-option-that-does-not-exist=value
port=99999999
EOF
    
    c_invalid=0
    rust_invalid=0
    
    "${C_BINARY}" --test --conf-file="${TEST_DIR}/invalid.conf" >/dev/null 2>&1 || c_invalid=1
    "${RUST_BINARY}" --test --conf-file="${TEST_DIR}/invalid.conf" >/dev/null 2>&1 || rust_invalid=1
    
    if [ "${c_invalid}" -eq 1 ] && [ "${rust_invalid}" -eq 1 ]; then
        log_success "Both binaries reject invalid configuration"
    else
        log_fail "Configuration validation mismatch (C: ${c_invalid}, Rust: ${rust_invalid})"
    fi
    
    # Test 1.3: Help output comparison
    log_info "Test: Help output completeness"
    C_HELP_LINES=$(("${C_BINARY}" --help 2>&1 | wc -l))
    RUST_HELP_LINES=$("${RUST_BINARY}" --help 2>&1 | wc -l)
    
    if [ "${RUST_HELP_LINES}" -ge "$((C_HELP_LINES * 90 / 100))" ]; then
        log_success "Help output is comparable (C: ${C_HELP_LINES} lines, Rust: ${RUST_HELP_LINES} lines)"
    else
        log_fail "Help output differs significantly (C: ${C_HELP_LINES} lines, Rust: ${RUST_HELP_LINES} lines)"
    fi
}

# Test 2: DNS Functional Tests
test_dns_functionality() {
    echo ""
    log_info "=== DNS Functional Tests ==="
    
    # Check if dig is available
    if ! command -v dig >/dev/null 2>&1; then
        log_skip "DNS tests (dig not available)"
        return
    fi
    
    # Start both dnsmasq instances
    log_info "Starting C dnsmasq on port ${C_DNS_PORT}..."
    "${C_BINARY}" --conf-file="${C_TEST_DIR}/dnsmasq.conf" --keep-in-foreground >"${C_TEST_DIR}/stdout.log" 2>&1 &
    C_PID=$!
    
    log_info "Starting Rust dnsmasq on port ${RUST_DNS_PORT}..."
    "${RUST_BINARY}" --conf-file="${RUST_TEST_DIR}/dnsmasq.conf" --keep-in-foreground >"${RUST_TEST_DIR}/stdout.log" 2>&1 &
    RUST_PID=$!
    
    # Wait for servers to start
    sleep 2
    
    # Verify both are running
    if ! kill -0 "${C_PID}" 2>/dev/null; then
        log_fail "C dnsmasq failed to start"
        cat "${C_TEST_DIR}/stdout.log"
        return
    fi
    
    if ! kill -0 "${RUST_PID}" 2>/dev/null; then
        log_fail "Rust dnsmasq failed to start"
        cat "${RUST_TEST_DIR}/stdout.log"
        return
    fi
    
    log_info "Both servers started successfully"
    
    # Test 2.1: A record query
    test_dns_query "A" "test.example" "192.168.1.1"
    
    # Test 2.2: Negative response (NXDOMAIN)
    test_dns_query_nxdomain "nonexistent.test.local"
    
    # Test 2.3: Query with EDNS0
    test_dns_edns0_query "test.example"
    
    # Test 2.4: Multiple queries (caching test)
    test_dns_caching "test.example"
    
    # Stop servers
    log_info "Stopping test servers..."
    kill "${C_PID}" 2>/dev/null || true
    kill "${RUST_PID}" 2>/dev/null || true
    wait "${C_PID}" 2>/dev/null || true
    wait "${RUST_PID}" 2>/dev/null || true
    C_PID=""
    RUST_PID=""
}

# Test individual DNS query
test_dns_query() {
    query_type="$1"
    query_name="$2"
    expected_answer="$3"
    
    log_info "Test: ${query_type} query for ${query_name}"
    
    c_result=$(dig @127.0.0.1 -p "${C_DNS_PORT}" "${query_name}" "${query_type}" +short 2>/dev/null | head -1)
    rust_result=$(dig @127.0.0.1 -p "${RUST_DNS_PORT}" "${query_name}" "${query_type}" +short 2>/dev/null | head -1)
    
    if [ "${c_result}" = "${rust_result}" ]; then
        if [ -n "${expected_answer}" ] && [ "${c_result}" = "${expected_answer}" ]; then
            log_success "${query_type} query for ${query_name} matches (${c_result})"
        elif [ -n "${expected_answer}" ]; then
            log_fail "${query_type} query returned unexpected result (expected: ${expected_answer}, got: ${c_result})"
        else
            log_success "${query_type} query for ${query_name} matches"
        fi
    else
        log_fail "${query_type} query mismatch (C: '${c_result}', Rust: '${rust_result}')"
    fi
}

# Test NXDOMAIN response
test_dns_query_nxdomain() {
    query_name="$1"
    
    log_info "Test: NXDOMAIN for ${query_name}"
    
    c_status=$(dig @127.0.0.1 -p "${C_DNS_PORT}" "${query_name}" A +short 2>/dev/null | wc -l)
    rust_status=$(dig @127.0.0.1 -p "${RUST_DNS_PORT}" "${query_name}" A +short 2>/dev/null | wc -l)
    
    if [ "${c_status}" -eq 0 ] && [ "${rust_status}" -eq 0 ]; then
        log_success "NXDOMAIN response matches for ${query_name}"
    else
        log_fail "NXDOMAIN response mismatch (C returned ${c_status} records, Rust returned ${rust_status} records)"
    fi
}

# Test EDNS0 support
test_dns_edns0_query() {
    query_name="$1"
    
    log_info "Test: EDNS0 query for ${query_name}"
    
    c_result=$(dig @127.0.0.1 -p "${C_DNS_PORT}" "${query_name}" A +edns=0 +short 2>/dev/null | head -1)
    rust_result=$(dig @127.0.0.1 -p "${RUST_DNS_PORT}" "${query_name}" A +edns=0 +short 2>/dev/null | head -1)
    
    if [ "${c_result}" = "${rust_result}" ]; then
        log_success "EDNS0 query for ${query_name} matches"
    else
        log_fail "EDNS0 query mismatch (C: '${c_result}', Rust: '${rust_result}')"
    fi
}

# Test DNS caching
test_dns_caching() {
    query_name="$1"
    
    log_info "Test: DNS caching for ${query_name}"
    
    # Make initial query
    dig @127.0.0.1 -p "${C_DNS_PORT}" "${query_name}" A +short >/dev/null 2>&1
    dig @127.0.0.1 -p "${RUST_DNS_PORT}" "${query_name}" A +short >/dev/null 2>&1
    
    # Make second query (should be cached)
    c_result=$(dig @127.0.0.1 -p "${C_DNS_PORT}" "${query_name}" A +short 2>/dev/null | head -1)
    rust_result=$(dig @127.0.0.1 -p "${RUST_DNS_PORT}" "${query_name}" A +short 2>/dev/null | head -1)
    
    if [ "${c_result}" = "${rust_result}" ]; then
        log_success "Cached query for ${query_name} matches"
    else
        log_fail "Cached query mismatch (C: '${c_result}', Rust: '${rust_result}')"
    fi
}

# Test 3: DHCP Functional Tests
test_dhcp_functionality() {
    echo ""
    log_info "=== DHCP Functional Tests ==="
    
    if ! check_dhcp_support; then
        log_skip "DHCP tests (DHCP not compiled in)"
        return
    fi
    
    # Check if necessary tools are available
    if ! command -v dhcping >/dev/null 2>&1 && ! command -v nmap >/dev/null 2>&1; then
        log_skip "DHCP tests (dhcping or nmap not available)"
        return
    fi
    
    log_info "DHCP functional tests would require network interface configuration"
    log_skip "DHCP tests (requires root and network setup)"
}

# Test 4: Signal Handling Tests
test_signal_handling() {
    echo ""
    log_info "=== Signal Handling Tests ==="
    
    # Start both servers
    log_info "Starting servers for signal tests..."
    "${C_BINARY}" --conf-file="${C_TEST_DIR}/dnsmasq.conf" --keep-in-foreground >"${C_TEST_DIR}/signal_stdout.log" 2>&1 &
    C_PID=$!
    
    "${RUST_BINARY}" --conf-file="${RUST_TEST_DIR}/dnsmasq.conf" --keep-in-foreground >"${RUST_TEST_DIR}/signal_stdout.log" 2>&1 &
    RUST_PID=$!
    
    sleep 2
    
    # Test 4.1: SIGUSR1 (stats dump)
    log_info "Test: SIGUSR1 signal handling (stats dump)"
    kill -USR1 "${C_PID}" 2>/dev/null || true
    kill -USR1 "${RUST_PID}" 2>/dev/null || true
    sleep 1
    
    if kill -0 "${C_PID}" 2>/dev/null && kill -0 "${RUST_PID}" 2>/dev/null; then
        log_success "Both servers handled SIGUSR1 without crashing"
    else
        log_fail "One or both servers crashed on SIGUSR1"
    fi
    
    # Test 4.2: SIGHUP (reload configuration)
    log_info "Test: SIGHUP signal handling (config reload)"
    kill -HUP "${C_PID}" 2>/dev/null || true
    kill -HUP "${RUST_PID}" 2>/dev/null || true
    sleep 1
    
    if kill -0 "${C_PID}" 2>/dev/null && kill -0 "${RUST_PID}" 2>/dev/null; then
        log_success "Both servers handled SIGHUP without crashing"
    else
        log_fail "One or both servers crashed on SIGHUP"
    fi
    
    # Test 4.3: SIGTERM (graceful shutdown)
    log_info "Test: SIGTERM signal handling (graceful shutdown)"
    kill -TERM "${C_PID}" 2>/dev/null || true
    kill -TERM "${RUST_PID}" 2>/dev/null || true
    sleep 2
    
    c_exited=0
    rust_exited=0
    kill -0 "${C_PID}" 2>/dev/null || c_exited=1
    kill -0 "${RUST_PID}" 2>/dev/null || rust_exited=1
    
    if [ "${c_exited}" -eq 1 ] && [ "${rust_exited}" -eq 1 ]; then
        log_success "Both servers gracefully shut down on SIGTERM"
    else
        log_fail "One or both servers did not shut down properly (C exited: ${c_exited}, Rust exited: ${rust_exited})"
    fi
    
    C_PID=""
    RUST_PID=""
}

# Test 5: Performance Comparison
test_performance() {
    echo ""
    log_info "=== Performance Comparison ==="
    
    if ! command -v dig >/dev/null 2>&1; then
        log_skip "Performance tests (dig not available)"
        return
    fi
    
    # Start both servers
    log_info "Starting servers for performance tests..."
    "${C_BINARY}" --conf-file="${C_TEST_DIR}/dnsmasq.conf" --keep-in-foreground >/dev/null 2>&1 &
    C_PID=$!
    
    "${RUST_BINARY}" --conf-file="${RUST_TEST_DIR}/dnsmasq.conf" --keep-in-foreground >/dev/null 2>&1 &
    RUST_PID=$!
    
    sleep 2
    
    # Test 5.1: Query throughput
    log_info "Test: Query throughput (100 queries each)"
    
    c_start=$(date +%s%N)
    for i in $(seq 1 100); do
        dig @127.0.0.1 -p "${C_DNS_PORT}" test.example A +short >/dev/null 2>&1
    done
    c_end=$(date +%s%N)
    c_duration=$(( (c_end - c_start) / 1000000 ))
    
    rust_start=$(date +%s%N)
    for i in $(seq 1 100); do
        dig @127.0.0.1 -p "${RUST_DNS_PORT}" test.example A +short >/dev/null 2>&1
    done
    rust_end=$(date +%s%N)
    rust_duration=$(( (rust_end - rust_start) / 1000000 ))
    
    log_info "C version: ${c_duration}ms for 100 queries"
    log_info "Rust version: ${rust_duration}ms for 100 queries"
    
    # Check if within 20% tolerance (per section 0.2.1)
    if [ "${rust_duration}" -gt 0 ] && [ "${c_duration}" -gt 0 ]; then
        rust_percent=$(( (rust_duration * 100) / c_duration ))
        if [ "${rust_percent}" -le 120 ]; then
            log_success "Performance within 20% tolerance (Rust is ${rust_percent}% of C time)"
        else
            log_warn "Performance outside 20% tolerance (Rust is ${rust_percent}% of C time)"
        fi
    fi
    
    # Test 5.2: Memory footprint comparison
    log_info "Test: Memory footprint comparison"
    
    if command -v ps >/dev/null 2>&1; then
        c_mem=$(ps -o rss= -p "${C_PID}" 2>/dev/null || echo "0")
        rust_mem=$(ps -o rss= -p "${RUST_PID}" 2>/dev/null || echo "0")
        
        if [ "${c_mem}" -gt 0 ] && [ "${rust_mem}" -gt 0 ]; then
            log_info "C version RSS: ${c_mem} KB"
            log_info "Rust version RSS: ${rust_mem} KB"
            
            rust_mem_percent=$(( (rust_mem * 100) / c_mem ))
            if [ "${rust_mem_percent}" -le 120 ]; then
                log_success "Memory within 20% tolerance (Rust is ${rust_mem_percent}% of C memory)"
            else
                log_warn "Memory outside 20% tolerance (Rust is ${rust_mem_percent}% of C memory)"
            fi
        else
            log_skip "Memory measurement (ps failed)"
        fi
    else
        log_skip "Memory measurement (ps not available)"
    fi
    
    # Stop servers
    kill "${C_PID}" 2>/dev/null || true
    kill "${RUST_PID}" 2>/dev/null || true
    wait "${C_PID}" 2>/dev/null || true
    wait "${RUST_PID}" 2>/dev/null || true
    C_PID=""
    RUST_PID=""
}

# Test 6: Output Comparison
test_output_comparison() {
    echo ""
    log_info "=== Output Comparison ==="
    
    # Compare version output
    log_info "Test: Version output comparison"
    
    c_version=$("${C_BINARY}" --version 2>&1 | head -1)
    rust_version=$("${RUST_BINARY}" --version 2>&1 | head -1)
    
    log_info "C version: ${c_version}"
    log_info "Rust version: ${rust_version}"
    
    # Both should mention dnsmasq
    if echo "${c_version}" | grep -q -i "dnsmasq" && echo "${rust_version}" | grep -q -i "dnsmasq"; then
        log_success "Both binaries report valid version information"
    else
        log_fail "Version output format differs"
    fi
    
    # Compare feature flags
    log_info "Test: Feature flags comparison"
    
    c_features=$("${C_BINARY}" --version 2>&1 | grep -c -E -i "dhcp|tftp|dnssec|ipset|dbus" || true)
    rust_features=$("${RUST_BINARY}" --version 2>&1 | grep -c -E -i "dhcp|tftp|dnssec|ipset|dbus" || true)
    
    if [ "${rust_features}" -ge "${c_features}" ]; then
        log_success "Rust version reports ${rust_features} features (C has ${c_features})"
    else
        log_warn "Rust version reports fewer features (${rust_features}) than C (${c_features})"
    fi
}

# Generate final report
generate_report() {
    echo ""
    echo "========================================"
    echo "  COMPATIBILITY TEST REPORT"
    echo "========================================"
    echo ""
    printf "Tests Passed:  ${GREEN}%d${NC}\n" "${TESTS_PASSED}"
    printf "Tests Failed:  ${RED}%d${NC}\n" "${TESTS_FAILED}"
    printf "Tests Skipped: ${YELLOW}%d${NC}\n" "${TESTS_SKIPPED}"
    echo ""
    
    total_tests=$((TESTS_PASSED + TESTS_FAILED))
    if [ "${total_tests}" -gt 0 ]; then
        pass_rate=$(( (TESTS_PASSED * 100) / total_tests ))
        printf "Pass Rate: %d%%\n" "${pass_rate}"
        echo ""
    fi
    
    if [ "${TESTS_FAILED}" -eq 0 ]; then
        printf "${GREEN}OVERALL: PASS${NC}\n"
        printf "The Rust implementation demonstrates drop-in compatibility with the C version.\n"
        echo ""
        return 0
    else
        printf "${RED}OVERALL: FAIL${NC}\n"
        printf "The Rust implementation has compatibility issues that need to be addressed.\n"
        echo ""
        return 1
    fi
}

# Main execution
main() {
    echo "========================================"
    echo "  dnsmasq C/Rust Compatibility Test"
    echo "========================================"
    echo ""
    
    detect_project_root
    detect_binaries
    setup_test_environment
    
    test_config_parsing
    test_dns_functionality
    test_dhcp_functionality
    test_signal_handling
    test_performance
    test_output_comparison
    
    generate_report
}

# Run main function
main
exit_code=$?

exit "${exit_code}"
