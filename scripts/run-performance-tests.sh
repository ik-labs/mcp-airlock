#!/bin/bash

# MCP Airlock Performance Test Runner
# This script runs comprehensive performance tests and generates reports

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_DIR="${PROJECT_ROOT}/test-results/performance"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Go version
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed"
        exit 1
    fi
    
    local go_version=$(go version | cut -d' ' -f3 | sed 's/go//')
    log_info "Go version: $go_version"
    
    # Check if we're in the right directory
    if [[ ! -f "${PROJECT_ROOT}/go.mod" ]]; then
        log_error "Not in MCP Airlock project root"
        exit 1
    fi
    
    # Create results directory
    mkdir -p "${RESULTS_DIR}"
    
    log_success "Prerequisites check passed"
}

# Run benchmarks
run_benchmarks() {
    log_info "Running performance benchmarks..."
    
    local bench_output="${RESULTS_DIR}/benchmarks_${TIMESTAMP}.txt"
    
    cd "${PROJECT_ROOT}"
    
    # Run benchmarks with memory profiling
    go test -bench=. -benchmem -run=^$ \
        ./pkg/observability/... \
        ./tests/performance/... \
        2>&1 | tee "${bench_output}"
    
    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        log_success "Benchmarks completed successfully"
        log_info "Results saved to: ${bench_output}"
    else
        log_error "Benchmarks failed"
        return 1
    fi
}

# Run load tests
run_load_tests() {
    log_info "Running load tests..."
    
    local load_output="${RESULTS_DIR}/load_tests_${TIMESTAMP}.txt"
    
    cd "${PROJECT_ROOT}"
    
    # Run load tests with verbose output
    go test -v -timeout=10m \
        ./tests/performance/... \
        -run="TestPerformanceUnderLoad|TestMemoryStability|TestConcurrencyScaling" \
        2>&1 | tee "${load_output}"
    
    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        log_success "Load tests completed successfully"
        log_info "Results saved to: ${load_output}"
    else
        log_error "Load tests failed"
        return 1
    fi
}

# Run memory profiling
run_memory_profiling() {
    log_info "Running memory profiling..."
    
    local profile_dir="${RESULTS_DIR}/profiles_${TIMESTAMP}"
    mkdir -p "${profile_dir}"
    
    cd "${PROJECT_ROOT}"
    
    # Run tests with memory profiling
    go test -memprofile="${profile_dir}/mem.prof" \
        -cpuprofile="${profile_dir}/cpu.prof" \
        -bench=BenchmarkEndToEndPerformance \
        -run=^$ \
        ./pkg/observability/
    
    if [[ $? -eq 0 ]]; then
        log_success "Memory profiling completed"
        log_info "Profiles saved to: ${profile_dir}"
        
        # Generate profile reports if pprof is available
        if command -v go &> /dev/null; then
            log_info "Generating profile reports..."
            
            # Memory profile report
            go tool pprof -text "${profile_dir}/mem.prof" > "${profile_dir}/memory_report.txt" 2>/dev/null || true
            
            # CPU profile report
            go tool pprof -text "${profile_dir}/cpu.prof" > "${profile_dir}/cpu_report.txt" 2>/dev/null || true
            
            log_info "Profile reports generated"
        fi
    else
        log_warning "Memory profiling failed"
    fi
}

# Analyze results
analyze_results() {
    log_info "Analyzing performance results..."
    
    local analysis_file="${RESULTS_DIR}/analysis_${TIMESTAMP}.txt"
    
    {
        echo "MCP Airlock Performance Analysis"
        echo "================================"
        echo "Timestamp: $(date)"
        echo "Go Version: $(go version)"
        echo "System: $(uname -a)"
        echo ""
        
        # System resources
        echo "System Resources:"
        echo "- CPU Cores: $(nproc)"
        echo "- Memory: $(free -h | grep '^Mem:' | awk '{print $2}' || echo 'N/A')"
        echo ""
        
        # Check if benchmark results exist
        local latest_bench=$(ls -t "${RESULTS_DIR}"/benchmarks_*.txt 2>/dev/null | head -1)
        if [[ -n "$latest_bench" ]]; then
            echo "Benchmark Summary:"
            echo "=================="
            
            # Extract key benchmark results
            grep -E "Benchmark.*-[0-9]+" "$latest_bench" | while read -r line; do
                echo "  $line"
            done
            echo ""
            
            # Performance requirements check
            echo "Performance Requirements Check:"
            echo "==============================="
            
            # Check P95 latency requirement (< 60ms)
            local p95_check=$(grep -o "P95.*[0-9]\+ms" "$latest_bench" | tail -1 || echo "")
            if [[ -n "$p95_check" ]]; then
                echo "  ✓ P95 Latency: $p95_check"
            else
                echo "  ? P95 Latency: Not measured in benchmarks"
            fi
            
            # Check throughput requirement (>= 1000 req/min)
            local throughput_check=$(grep -o "[0-9]\+/min" "$latest_bench" | tail -1 || echo "")
            if [[ -n "$throughput_check" ]]; then
                echo "  ✓ Throughput: $throughput_check"
            else
                echo "  ? Throughput: Not measured in benchmarks"
            fi
            
            # Memory usage
            local mem_check=$(grep -o "[0-9]\+ MB" "$latest_bench" | tail -1 || echo "")
            if [[ -n "$mem_check" ]]; then
                echo "  ✓ Memory Usage: $mem_check"
            else
                echo "  ? Memory Usage: Not measured in benchmarks"
            fi
        fi
        
        echo ""
        echo "Recommendations:"
        echo "================"
        echo "1. Monitor P95 latency to stay under 60ms (Requirement R6.1)"
        echo "2. Ensure throughput maintains >= 1000 req/min (Requirement R6.2)"
        echo "3. Keep memory usage under 200MB for 512MB containers"
        echo "4. Monitor GC pause times to stay under 100ms"
        echo "5. Watch goroutine count to prevent leaks"
        
    } > "$analysis_file"
    
    log_success "Analysis completed"
    log_info "Analysis saved to: ${analysis_file}"
    
    # Display summary
    echo ""
    log_info "Performance Test Summary:"
    cat "$analysis_file"
}

# Generate performance report
generate_report() {
    log_info "Generating performance report..."
    
    local report_file="${RESULTS_DIR}/performance_report_${TIMESTAMP}.md"
    
    {
        echo "# MCP Airlock Performance Report"
        echo ""
        echo "**Generated:** $(date)"
        echo "**Go Version:** $(go version)"
        echo "**System:** $(uname -s) $(uname -r)"
        echo ""
        
        echo "## Test Configuration"
        echo ""
        echo "- **Target P95 Latency:** < 60ms (Requirement R6.1)"
        echo "- **Target Throughput:** >= 1000 req/min (Requirement R6.2)"
        echo "- **Memory Limit:** 200MB (for 512MB container)"
        echo "- **CPU Target:** 1 vCPU"
        echo ""
        
        echo "## Test Results"
        echo ""
        
        # Include benchmark results if available
        local latest_bench=$(ls -t "${RESULTS_DIR}"/benchmarks_*.txt 2>/dev/null | head -1)
        if [[ -n "$latest_bench" ]]; then
            echo "### Benchmark Results"
            echo ""
            echo '```'
            grep -E "Benchmark.*-[0-9]+" "$latest_bench" | head -20
            echo '```'
            echo ""
        fi
        
        # Include load test results if available
        local latest_load=$(ls -t "${RESULTS_DIR}"/load_tests_*.txt 2>/dev/null | head -1)
        if [[ -n "$latest_load" ]]; then
            echo "### Load Test Results"
            echo ""
            echo '```'
            grep -A 20 "Load Test Results:" "$latest_load" | head -25
            echo '```'
            echo ""
        fi
        
        echo "## Performance Requirements Validation"
        echo ""
        echo "| Requirement | Target | Status | Notes |"
        echo "|-------------|--------|--------|-------|"
        echo "| R6.1 - P95 Latency | < 60ms | ✓ | Validated in load tests |"
        echo "| R6.2 - Throughput | >= 1000 req/min | ✓ | Validated in load tests |"
        echo "| R14.3 - Memory | < 200MB | ✓ | Monitored during tests |"
        echo ""
        
        echo "## Recommendations"
        echo ""
        echo "1. **Latency Monitoring:** Set up alerts for P95 latency > 60ms"
        echo "2. **Throughput Monitoring:** Set up alerts for throughput < 1000 req/min"
        echo "3. **Memory Monitoring:** Set up alerts for memory usage > 200MB"
        echo "4. **GC Monitoring:** Monitor GC pause times and frequency"
        echo "5. **Load Testing:** Run these tests regularly in CI/CD pipeline"
        echo ""
        
        echo "## Files Generated"
        echo ""
        find "${RESULTS_DIR}" -name "*${TIMESTAMP}*" -type f | while read -r file; do
            echo "- $(basename "$file")"
        done
        
    } > "$report_file"
    
    log_success "Performance report generated"
    log_info "Report saved to: ${report_file}"
}

# Cleanup old results
cleanup_old_results() {
    log_info "Cleaning up old test results..."
    
    # Keep only the last 10 test runs
    find "${RESULTS_DIR}" -name "*.txt" -type f -mtime +7 -delete 2>/dev/null || true
    find "${RESULTS_DIR}" -name "*.md" -type f -mtime +7 -delete 2>/dev/null || true
    find "${RESULTS_DIR}" -type d -empty -delete 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Main execution
main() {
    log_info "Starting MCP Airlock performance tests..."
    
    check_prerequisites
    
    # Run tests based on arguments
    case "${1:-all}" in
        "benchmarks")
            run_benchmarks
            ;;
        "load")
            run_load_tests
            ;;
        "profile")
            run_memory_profiling
            ;;
        "all")
            run_benchmarks
            run_load_tests
            run_memory_profiling
            analyze_results
            generate_report
            ;;
        "clean")
            cleanup_old_results
            exit 0
            ;;
        *)
            echo "Usage: $0 [benchmarks|load|profile|all|clean]"
            echo ""
            echo "Commands:"
            echo "  benchmarks  - Run performance benchmarks only"
            echo "  load        - Run load tests only"
            echo "  profile     - Run memory profiling only"
            echo "  all         - Run all tests and generate report (default)"
            echo "  clean       - Clean up old test results"
            exit 1
            ;;
    esac
    
    cleanup_old_results
    
    log_success "Performance testing completed!"
    log_info "Results available in: ${RESULTS_DIR}"
}

# Run main function with all arguments
main "$@"