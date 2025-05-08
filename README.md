# CKKS Benchmarking with SGX and Gramine

This repository compares two implementations of **CKKS (Cheon-Kim-Kim-Song)** homomorphic encryption scheme in **Intel SGX (Software Guard Extensions)**.

## Overview

This repository contains two main components for benchmarking CKKS encryption:

- **Gramine-based Implementation**: Utilizes Gramine to run OpenFHE library benchmarks in a secure environment with Intel SGX.
- **Custom SDK Implementation**: A basic CKKS implementation integrated with Intel SGX for secure execution within an enclave.

## Getting Started

### Prerequisites

- **Intel SGX SDK**: Required for building and running the custom SGX implementation.
- **Gramine**: Needed for running the OpenFHE benchmarks in a secure environment.
- **OpenFHE Library**: Must be installed for the Gramine-based benchmarks (```/usr/local/lib```).
- **SGX-enabled Hardware**: Necessary for running applications in a secure enclave.

### Building the Project

1. **Gramine Implementation**:

  - Navigate to the ```Gramine``` directory.
  - Run ```make``` to build the encryption and decryption benchmark binaries.
2. **SDK Implementation**:

  - Navigate to the ```SDK``` directory.
  - Run ```make``` to build the CKKS application and enclave.

### Running Benchmarks

- **Gramine Benchmarks**:

  - In the ```Gramine``` directory, execute ```./benchmark_openfhe.sh [iterations]``` to run both encryption and decryption benchmarks. Replace ```[iterations]``` with the desired number of iterations (default is 100).
  - **Key Output**: The script provides metrics like **time per operation**, **operations per second**, and **total time** for both encryption and decryption.
- **SDK Benchmarks**:

  - In the ```SDK``` directory, execute ```./benchmark.sh [iterations]``` to run the custom SGX CKKS benchmarks.
  - **Key Output**: Similar metrics are provided as in the Gramine benchmarks, tailored to the custom implementation.

### Usage Notes

- Both benchmark scripts include warm-up iterations to stabilize performance measurements.
- The SDK implementation automatically generates and saves encryption keys if they are not already present.
- Ensure that the polynomial degree and scale parameters are appropriately set for your use case (default values are provided in the scripts).