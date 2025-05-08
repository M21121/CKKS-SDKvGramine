#!/bin/bash

# Combined SGX CKKS Benchmark Script
# Usage: ./benchmark.sh [iterations]

ITERATIONS=${1:-100}
WARMUP_ITERATIONS=5
POLY_DEGREE=8192
SCALE=1073741824  # 2^30

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Custom SGX CKKS Comprehensive Benchmark ===${NC}"
echo "Iterations: $ITERATIONS"
echo "Warm-up Iterations: $WARMUP_ITERATIONS"
echo "Polynomial Degree: $POLY_DEGREE"
echo "Scale: $SCALE"
echo "=============================================="

# Generate keys if they don't exist
if [ ! -f "ckks_secret_key.bin" ] || [ ! -f "ckks_public_key.bin" ]; then
    echo -e "${BLUE}Generating keys...${NC}"
    ./ckks_app genkeys 1 $POLY_DEGREE $SCALE
fi

# Function to run benchmark for a specific mode
run_benchmark() {
    local mode=$1

    # Warm-up runs
    echo -e "${BLUE}Running warm-up for $mode...${NC}"
    for ((i=1; i<=$WARMUP_ITERATIONS; i++))
    do
        ./ckks_app $mode 1 $POLY_DEGREE $SCALE > /dev/null 2>&1
    done

    # Actual benchmark with external timing
    echo -e "${BLUE}Running $mode benchmark...${NC}"
    start_time=$(date +%s.%N)
    ./ckks_app $mode $ITERATIONS $POLY_DEGREE $SCALE > /dev/null 2>&1
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc -l)

    # Calculate metrics
    ms_per_op=$(echo "scale=2; 1000 * $duration / $ITERATIONS" | bc -l)
    ops_per_sec=$(echo "scale=2; $ITERATIONS / $duration" | bc -l)

    echo -e "${GREEN}$mode time per operation: $ms_per_op ms${NC}"
    echo -e "${GREEN}$mode operations per second: $ops_per_sec${NC}"
    echo -e "${GREEN}Total $mode time: $(echo "scale=3; $duration" | bc -l) seconds${NC}"
    echo "--------------------------------------------"
}

# Run encryption benchmark
run_benchmark "encrypt"

# Run decryption benchmark
run_benchmark "decrypt"

echo -e "${YELLOW}Benchmark complete!${NC}"

