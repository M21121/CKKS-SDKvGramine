#!/bin/bash

# Combined OpenFHE with Gramine Benchmark Script
# Usage: ./benchmark_openfhe.sh [iterations]

ITERATIONS=${1:-10000}
WARMUP_ITERATIONS=5

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== OpenFHE with Gramine Comprehensive Benchmark ===${NC}"
echo "Iterations: $ITERATIONS"
echo "Warm-up Iterations: $WARMUP_ITERATIONS"
echo "=============================================="

# Check if SGX is enabled and manifest files exist
SGX_ENABLED=0
if [ -f "./encrypt_benchmark.manifest.sgx" ] && [ -f "./decrypt_benchmark.manifest.sgx" ]; then
    SGX_ENABLED=1
fi

# Function to run benchmark for a specific mode
run_benchmark() {
    local mode=$1
    local binary

    if [ "$mode" == "encrypt" ]; then
        binary="./encrypt_benchmark"
    else
        binary="./decrypt_benchmark"
    fi

    # Warm-up runs
    echo -e "${BLUE}Running warm-up for $mode...${NC}"
    for ((i=1; i<=$WARMUP_ITERATIONS; i++))
    do
        if [ "$SGX_ENABLED" -eq 1 ]; then
            gramine-sgx $binary 1 > /dev/null 2>&1
        else
            $binary 1 > /dev/null 2>&1
        fi
    done

    # Actual benchmark
    echo -e "${BLUE}Running $mode benchmark...${NC}"
    if [ "$SGX_ENABLED" -eq 1 ]; then
        gramine-sgx $binary $ITERATIONS
    else
        $binary $ITERATIONS
    fi
    echo "--------------------------------------------"
}

# Run encryption benchmark
run_benchmark "encrypt"

# Run decryption benchmark
run_benchmark "decrypt"

echo -e "${YELLOW}Benchmark complete!${NC}"
