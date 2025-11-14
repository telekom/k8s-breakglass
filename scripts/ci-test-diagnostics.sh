#!/bin/bash
# CI Test Diagnostics Helper
# This script provides enhanced error handling and diagnostics for unit tests in CI environments

set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_OUTPUT_FILE="${TEST_OUTPUT_FILE:-test-output.log}"
COVERAGE_FILE="${COVERAGE_FILE:-cover.out}"
TIMEOUT="${TEST_TIMEOUT:-300}"  # 5 minutes default
VERBOSE="${VERBOSE:-false}"

echo -e "${BLUE}=== CI TEST ENVIRONMENT DIAGNOSTICS ===${NC}"
echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "Hostname: $(hostname)"
echo "Working Directory: $(pwd)"
echo ""

echo -e "${BLUE}=== SYSTEM INFORMATION ===${NC}"
echo "OS: $(uname -s)"
echo "Arch: $(uname -m)"
echo "CPU Cores: $(nproc)"
echo ""

echo -e "${BLUE}=== GO INFORMATION ===${NC}"
go version
echo "Go Module: $(grep '^module' go.mod | awk '{print $2}')"
echo ""

echo -e "${BLUE}=== GO ENVIRONMENT ===${NC}"
go env | head -10
echo ""

echo -e "${BLUE}=== RUNNING TESTS ===${NC}"
TEST_START=$(date +%s)

# Run tests with enhanced output
go test $(go list ./... | grep -v /e2e) \
    -coverprofile="${COVERAGE_FILE}" \
    -timeout="${TIMEOUT}s" \
    -v \
    -race \
    2>&1 | tee "${TEST_OUTPUT_FILE}"

TEST_EXIT_CODE=$?
TEST_END=$(date +%s)
TEST_DURATION=$((TEST_END - TEST_START))

echo ""
echo -e "${BLUE}=== TEST EXECUTION SUMMARY ===${NC}"
echo "Duration: ${TEST_DURATION}s"
echo "Exit Code: ${TEST_EXIT_CODE}"
echo ""

# Parse test results
TOTAL_PACKAGES=$(grep "^ok\|^FAIL" "${TEST_OUTPUT_FILE}" | wc -l)
PASSED_PACKAGES=$(grep "^ok " "${TEST_OUTPUT_FILE}" | wc -l)
FAILED_PACKAGES=$(grep "^FAIL" "${TEST_OUTPUT_FILE}" | wc -l)

echo "Total Packages: ${TOTAL_PACKAGES}"
echo -e "Passed Packages: ${GREEN}${PASSED_PACKAGES}${NC}"
echo -e "Failed Packages: ${RED}${FAILED_PACKAGES}${NC}"
echo ""

if [ ${TEST_EXIT_CODE} -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
    
    # Show coverage summary if available
    if [ -f "${COVERAGE_FILE}" ]; then
        echo ""
        echo -e "${BLUE}=== COVERAGE SUMMARY ===${NC}"
        go tool cover -func="${COVERAGE_FILE}" | tail -1
    fi
else
    echo -e "${RED}✗ TESTS FAILED${NC}"
    echo ""
    
    # Show failed packages
    if grep -q "^FAIL" "${TEST_OUTPUT_FILE}"; then
        echo -e "${YELLOW}=== FAILED PACKAGES ===${NC}"
        grep "^FAIL" "${TEST_OUTPUT_FILE}"
        echo ""
    fi
    
    # Show test failures
    if grep -q "^--- FAIL:" "${TEST_OUTPUT_FILE}"; then
        echo -e "${YELLOW}=== TEST FAILURES ===${NC}"
        grep "^--- FAIL:" "${TEST_OUTPUT_FILE}" | sort | uniq -c
        echo ""
        
        echo -e "${YELLOW}=== FAILURE DETAILS ===${NC}"
        grep -A 15 "^--- FAIL:" "${TEST_OUTPUT_FILE}" | head -100
        echo ""
    fi
    
    # Show panics and runtime errors
    if grep -qE "panic|fatal error|runtime error" "${TEST_OUTPUT_FILE}"; then
        echo -e "${YELLOW}=== PANICS/RUNTIME ERRORS ===${NC}"
        grep -B 2 -A 5 -E "panic|fatal error|runtime error" "${TEST_OUTPUT_FILE}" | head -50
        echo ""
    fi
    
    # Show last part of output for context
    echo -e "${YELLOW}=== TEST OUTPUT (Last 50 Lines) ===${NC}"
    tail -50 "${TEST_OUTPUT_FILE}"
fi

echo ""
echo -e "${BLUE}=== TEST LOG SAVED ===${NC}"
echo "Full output: ${TEST_OUTPUT_FILE}"
echo "Coverage report: ${COVERAGE_FILE}"

exit ${TEST_EXIT_CODE}
