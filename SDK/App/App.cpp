#include "sgx_urts.h"
#include "Enclave_u.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <string>

sgx_enclave_id_t global_eid = 0;

int initialize_enclave() {
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t ret = sgx_create_enclave("./enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    return (ret == SGX_SUCCESS) ? 0 : -1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [genkeys|encrypt|decrypt] [iterations] [polyDegree] [scale]" << std::endl;
        return -1;
    }

    std::string mode = argv[1];
    int iterations = (argc > 2) ? std::stoi(argv[2]) : 100;
    int polyDegree = (argc > 3) ? std::stoi(argv[3]) : 8192;
    double scale = (argc > 4) ? std::stod(argv[4]) : (1 << 30);
    int slots = polyDegree / 2;

    if (initialize_enclave() < 0) {
        std::cerr << "Failed to initialize enclave." << std::endl;
        return -1;
    }

    sgx_status_t ret, status;

    // Initialize CKKS
    status = ecall_init_ckks(global_eid, &ret, polyDegree, scale);
    if (status != SGX_SUCCESS || ret != SGX_SUCCESS) {
        std::cerr << "Failed to initialize CKKS" << std::endl;
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    if (mode == "genkeys") {
        // Generate keys and save them
        status = ecall_generate_keys(global_eid, &ret);
        if (status != SGX_SUCCESS || ret != SGX_SUCCESS) {
            std::cerr << "Failed to generate keys" << std::endl;
            sgx_destroy_enclave(global_eid);
            return -1;
        }

        // Save keys to file
        status = ecall_save_keys(global_eid, &ret);
        if (status != SGX_SUCCESS || ret != SGX_SUCCESS) {
            std::cerr << "Failed to save keys" << std::endl;
            sgx_destroy_enclave(global_eid);
            return -1;
        }

        std::cout << "Keys generated and saved successfully" << std::endl;
    }
    else {
        // Load keys from file
        status = ecall_load_keys(global_eid, &ret);
        if (status != SGX_SUCCESS || ret != SGX_SUCCESS) {
            std::cerr << "Failed to load keys" << std::endl;
            sgx_destroy_enclave(global_eid);
            return -1;
        }

        // Prepare message data
        std::vector<double> msg_real(slots, 0.0);
        std::vector<double> msg_imag(slots, 0.0);

        // Set some test values
        for (int i = 0; i < slots; i++) {
            msg_real[i] = i * 1.1;
            msg_imag[i] = i * 0.5;
        }

        // Prepare ciphertext buffer
        uint32_t ct_size = 2 * polyDegree;
        std::vector<int64_t> ciphertext(ct_size, 0);

        // Prepare result buffers for decryption
        std::vector<double> result_real(slots, 0.0);
        std::vector<double> result_imag(slots, 0.0);

        if (mode == "encrypt") {
            // Run encryption benchmark
            for (int i = 0; i < iterations; i++) {
                status = ecall_encrypt(global_eid, &ret, msg_real.data(), msg_imag.data(),
                                      slots, ciphertext.data(), ct_size);
                if (status != SGX_SUCCESS || ret != SGX_SUCCESS) {
                    std::cerr << "Encryption failed at iteration " << i << std::endl;
                    sgx_destroy_enclave(global_eid);
                    return -1;
                }
            }
        }
        else if (mode == "decrypt") {
            // First encrypt once to get a valid ciphertext
            status = ecall_encrypt(global_eid, &ret, msg_real.data(), msg_imag.data(),
                                  slots, ciphertext.data(), ct_size);
            if (status != SGX_SUCCESS || ret != SGX_SUCCESS) {
                std::cerr << "Initial encryption failed" << std::endl;
                sgx_destroy_enclave(global_eid);
                return -1;
            }

            // Run decryption benchmark
            for (int i = 0; i < iterations; i++) {
                status = ecall_decrypt(global_eid, &ret, ciphertext.data(), ct_size,
                                      result_real.data(), result_imag.data(), slots);
                if (status != SGX_SUCCESS || ret != SGX_SUCCESS) {
                    std::cerr << "Decryption failed at iteration " << i << std::endl;
                    sgx_destroy_enclave(global_eid);
                    return -1;
                }
            }
        }
        else {
            std::cerr << "Unknown mode: " << mode << std::endl;
            sgx_destroy_enclave(global_eid);
            return -1;
        }
    }

    // Cleanup
    sgx_destroy_enclave(global_eid);
    return 0;
}

void ocall_print_string(const char* str) { std::cout << str; }
void ocall_print_int(int64_t value) { std::cout << value; }
void ocall_print_double(double value) { std::cout << value; }
void ocall_save_data(const uint8_t* data, size_t len, const char* filename) {
    FILE* f = fopen(filename, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
    }
}
void ocall_load_data(uint8_t* data, size_t len, const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (f) {
        fread(data, 1, len, f);
        fclose(f);
    }
}
