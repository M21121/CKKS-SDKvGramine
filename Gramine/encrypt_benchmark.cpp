// encrypt_benchmark.cpp
#include "openfhe.h"
#include <chrono>
#include <iostream>

using namespace lbcrypto;
using namespace std::chrono;

int main(int argc, char* argv[]) {
    int iterations = (argc > 1) ? std::stoi(argv[1]) : 10000; // Default to 10000 if not provided
    std::cout << "Running encryption benchmark for " << iterations << " iterations..." << std::endl;

    // Setup parameters similar to the custom CKKS implementation
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetBatchSize(8192);
    parameters.SetScalingModSize(30);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);

    // Generate keys
    std::cout << "Generating keys..." << std::endl;
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

    // Prepare test data
    std::vector<double> vectorOfDoubles(4096, 0.0);
    for (int i = 0; i < 4096; i++) {
        vectorOfDoubles[i] = i * 1.1;
    }

    Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(vectorOfDoubles);

    // Run benchmark
    auto start = high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start).count();

    // Output results
    std::cout << "\nEncryption benchmark results:" << std::endl;
    std::cout << "Total time: " << duration << " ms" << std::endl;
    std::cout << "Average time per encryption: " << (double)duration / iterations << " ms" << std::endl;
    std::cout << "Operations per second: " << (iterations * 1000.0) / duration << std::endl;

    return 0;
}
