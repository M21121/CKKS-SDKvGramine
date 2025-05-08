// decrypt_benchmark.cpp
#include "openfhe.h"
#include <chrono>
#include <iostream>

using namespace lbcrypto;
using namespace std::chrono;

int main(int argc, char* argv[]) {
    int iterations = (argc > 1) ? std::stoi(argv[1]) : 100; // Default to 100 if not provided
    std::cout << "Running decryption benchmark for " << iterations << " iterations..." << std::endl;

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
    std::vector<double> vectorOfDoubles(4096, 0.0); // Half of poly degree
    for (int i = 0; i < 4096; i++) {
        vectorOfDoubles[i] = i * 1.1;
    }

    Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(vectorOfDoubles);

    // First encrypt once to get a valid ciphertext
    auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);

    // Run benchmark
    auto start = high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        Plaintext decryptedPlaintext;
        cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &decryptedPlaintext);
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start).count();

    // Output results
    std::cout << "Decryption benchmark results:" << std::endl;
    std::cout << "Total time: " << duration << " ms" << std::endl;
    std::cout << "Average time per decryption: " << (double)duration / iterations << " ms" << std::endl;
    std::cout << "Operations per second: " << (iterations * 1000.0) / duration << std::endl;

    return 0;
}
