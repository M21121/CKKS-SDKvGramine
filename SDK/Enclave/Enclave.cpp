#include "Enclave_t.h"
#include "sgx_trts.h"
#include "CKKS.h"
#include <string.h>

static CKKS* g_ckks = NULL;

sgx_status_t ecall_init_ckks(int polyDegree, double scale) {
    if (g_ckks != NULL) {
        delete g_ckks;
    }

    CKKSParams params;
    params.polyDegree = (uint32_t)polyDegree;
    params.scale = scale;
    params.slots = (uint32_t)(polyDegree / 2);

    g_ckks = new CKKS(params);
    return (g_ckks != NULL) ? SGX_SUCCESS : SGX_ERROR_OUT_OF_MEMORY;
}

sgx_status_t ecall_generate_keys() {
    return (g_ckks != NULL) ? g_ckks->keyGen() : SGX_ERROR_UNEXPECTED;
}

sgx_status_t ecall_save_keys() {
    if (g_ckks == NULL) return SGX_ERROR_UNEXPECTED;

    // Save secret key
    ocall_save_data((const uint8_t*)g_ckks->getSecretKey(),
                    g_ckks->getPolyDegree() * sizeof(int64_t),
                    "ckks_secret_key.bin");

    // Save public key
    ocall_save_data((const uint8_t*)g_ckks->getPublicKey(),
                    2 * g_ckks->getPolyDegree() * sizeof(int64_t),
                    "ckks_public_key.bin");

    return SGX_SUCCESS;
}

sgx_status_t ecall_load_keys() {
    if (g_ckks == NULL) return SGX_ERROR_UNEXPECTED;

    // Load secret key
    ocall_load_data((uint8_t*)g_ckks->getSecretKey(),
                   g_ckks->getPolyDegree() * sizeof(int64_t),
                   "ckks_secret_key.bin");

    // Load public key
    ocall_load_data((uint8_t*)g_ckks->getPublicKey(),
                   2 * g_ckks->getPolyDegree() * sizeof(int64_t),
                   "ckks_public_key.bin");

    return SGX_SUCCESS;
}

sgx_status_t ecall_encrypt(const double* msg_real, const double* msg_imag, 
                          uint32_t msg_len, int64_t* ciphertext, uint32_t ct_len) {
    return (g_ckks != NULL) ? g_ckks->encrypt(msg_real, msg_imag, msg_len, ciphertext, ct_len) : SGX_ERROR_UNEXPECTED;
}

sgx_status_t ecall_decrypt(const int64_t* ciphertext, uint32_t ct_len,
                          double* msg_real, double* msg_imag, uint32_t msg_len) {
    return (g_ckks != NULL) ? g_ckks->decrypt(ciphertext, ct_len, msg_real, msg_imag, msg_len) : SGX_ERROR_UNEXPECTED;
}
