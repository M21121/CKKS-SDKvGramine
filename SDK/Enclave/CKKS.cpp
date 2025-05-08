#include "CKKS.h"
#include "sgx_trts.h"
#include <string.h>
#include <math.h>
#include "Enclave_t.h"

CKKS::CKKS(const CKKSParams& p) {
    this->params.polyDegree = (p.polyDegree > MAX_POLY_DEGREE) ? MAX_POLY_DEGREE : p.polyDegree;
    this->params.scale = p.scale;
    this->params.slots = p.slots;
}

CKKS::~CKKS() {
    memset(&keys, 0, sizeof(keys));
}

int64_t CKKS::sampleTernary() {
    uint8_t rand_byte;
    sgx_read_rand(&rand_byte, 1);
    uint8_t val = rand_byte % 3;
    return (val == 0) ? -1 : ((val == 1) ? 1 : 0);
}

int64_t CKKS::sampleError() {
    uint8_t rand_bytes[2];
    sgx_read_rand(rand_bytes, 2);
    uint16_t rand_val = (uint16_t)rand_bytes[0] | ((uint16_t)rand_bytes[1] << 8);
    double u = rand_val / 65536.0;

    if (u < 0.383) return 0;
    else if (u < 0.683) return (rand_bytes[0] & 1) ? 1 : -1;
    else if (u < 0.866) return (rand_bytes[0] & 1) ? 2 : -2;
    else if (u < 0.954) return (rand_bytes[0] & 1) ? 3 : -3;
    else if (u < 0.987) return (rand_bytes[0] & 1) ? 4 : -4;
    else return (rand_bytes[0] & 1) ? 5 : -5;
}

sgx_status_t CKKS::keyGen() {
    // Generate secret key with ternary distribution
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        keys.secretKey[i] = sampleTernary();
    }

    // Modulus for coefficients
    const int64_t q = (1LL << 40);

    // Generate public key: (-(a*s + e), a)
    int64_t a[MAX_POLY_DEGREE];
    sgx_status_t status = sgx_read_rand((unsigned char*)a, params.polyDegree * sizeof(int64_t));
    if (status != SGX_SUCCESS) return status;

    // Ensure 'a' values are properly reduced modulo q
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        a[i] = ((a[i] % q) + q) % q;
    }

    // Generate small error
    int64_t e[MAX_POLY_DEGREE];
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        e[i] = sampleError();
    }

    // Compute -(a*s + e)
    int64_t as[MAX_POLY_DEGREE];
    polyMul(a, keys.secretKey, as, params.polyDegree);

    for (uint32_t i = 0; i < params.polyDegree; i++) {
        keys.publicKey[i] = (-(as[i] + e[i]) % q + q) % q;
        keys.publicKey[i + params.polyDegree] = a[i];
    }

    return SGX_SUCCESS;
}

sgx_status_t CKKS::encrypt(const double* msg_real, const double* msg_imag, 
                          uint32_t msg_len, int64_t* ciphertext, uint32_t ct_capacity) {
    if (ct_capacity < 2 * params.polyDegree) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Encode message into polynomial
    int64_t m[MAX_POLY_DEGREE] = {0};
    sgx_status_t status = encode(msg_real, msg_imag, msg_len, m, MAX_POLY_DEGREE);
    if (status != SGX_SUCCESS) return status;

    // Encrypt the polynomial
    const int64_t q = (1LL << 40);

    // Generate small error polynomials
    int64_t e1[MAX_POLY_DEGREE] = {0};
    int64_t e2[MAX_POLY_DEGREE] = {0};
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        e1[i] = sampleError();
        e2[i] = sampleError();
    }

    // Generate random polynomial for encryption
    int64_t u[MAX_POLY_DEGREE] = {0};
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        u[i] = sampleTernary();
    }

    // Compute c0 = b*u + e1 + m
    int64_t bu[MAX_POLY_DEGREE] = {0};
    polyMul(keys.publicKey, u, bu, params.polyDegree);

    // Compute c1 = a*u + e2
    int64_t au[MAX_POLY_DEGREE] = {0};
    polyMul(keys.publicKey + params.polyDegree, u, au, params.polyDegree);

    // Construct ciphertext
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        // c0 = b*u + e1 + m
        int64_t sum_c0 = 0;
        sum_c0 = (sum_c0 + bu[i]) % q;
        sum_c0 = (sum_c0 + e1[i]) % q;
        sum_c0 = (sum_c0 + m[i]) % q;
        ciphertext[i] = (sum_c0 + q) % q;

        // c1 = a*u + e2
        int64_t sum_c1 = 0;
        sum_c1 = (sum_c1 + au[i]) % q;
        sum_c1 = (sum_c1 + e2[i]) % q;
        ciphertext[i + params.polyDegree] = (sum_c1 + q) % q;
    }

    return SGX_SUCCESS;
}

sgx_status_t CKKS::decrypt(const int64_t* ciphertext, uint32_t ct_len,
                           double* msg_real, double* msg_imag, uint32_t msg_capacity) {
     if (ct_len < 2 * params.polyDegree) {
         return SGX_ERROR_INVALID_PARAMETER;
     }

     const int64_t q = (1LL << 40);

     // Compute c0 + c1*s
     int64_t c1s[MAX_POLY_DEGREE] = {0};
     polyMul(ciphertext + params.polyDegree, keys.secretKey, c1s, params.polyDegree);

     int64_t m[MAX_POLY_DEGREE] = {0};
     for (uint32_t i = 0; i < params.polyDegree; i++) {
         m[i] = (ciphertext[i] + c1s[i]) % q;
         if (m[i] > q/2) m[i] -= q;  // Ensure values are in [-q/2, q/2]
     }

     // Decode the polynomial to get the message
     return decode(m, params.polyDegree, msg_real, msg_imag, msg_capacity);
}

sgx_status_t CKKS::encode(const double* msg_real, const double* msg_imag, 
                         uint32_t msg_len, int64_t* polynomial, uint32_t poly_capacity) {
    if (poly_capacity < params.polyDegree) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (msg_len > params.slots) {
        msg_len = params.slots; // Truncate if too many values
    }

    // Prepare complex values for FFT
    complex_t message[MAX_POLY_DEGREE];
    memset(message, 0, sizeof(message));

    // Place values in the first half of the array
    for (uint32_t i = 0; i < msg_len; i++) {
        message[i].real = msg_real[i];
        message[i].imag = msg_imag[i];
    }

    // Handle complex conjugate symmetry for real FFT
    for (uint32_t i = 1; i < params.slots; i++) {
        if (i < msg_len) {
            message[params.polyDegree - i].real = msg_real[i];
            message[params.polyDegree - i].imag = -msg_imag[i];
        } else {
            message[params.polyDegree - i].real = 0;
            message[params.polyDegree - i].imag = 0;
        }
    }

    // Perform inverse FFT to get polynomial coefficients
    complex_t coeffs[MAX_POLY_DEGREE];
    memset(coeffs, 0, sizeof(coeffs));

    fft(message, coeffs, params.polyDegree, true);

    // Scale and round to integers
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        polynomial[i] = (int64_t)round(coeffs[i].real * params.scale);
    }

    return SGX_SUCCESS;
}

sgx_status_t CKKS::decode(const int64_t* polynomial, uint32_t poly_len,
                         double* msg_real, double* msg_imag, uint32_t msg_capacity) {
    if (poly_len < params.polyDegree || msg_capacity < params.slots) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    const int64_t q = (1LL << 40);

    // Convert integer polynomial to complex coefficients
    complex_t coeffs[MAX_POLY_DEGREE];
    memset(coeffs, 0, sizeof(coeffs));

    for (uint32_t i = 0; i < params.polyDegree; i++) {
        int64_t value = polynomial[i] % q;
        if (value > q/2) value -= q;
        coeffs[i].real = (double)value / params.scale;
        coeffs[i].imag = 0.0;
    }

    // Perform FFT to get the encoded slots
    complex_t message[MAX_POLY_DEGREE];
    memset(message, 0, sizeof(message));

    fft(coeffs, message, params.polyDegree, false);

    // Extract the message (only the first slots contain the actual data)
    for (uint32_t i = 0; i < params.slots && i < msg_capacity; i++) {
        msg_real[i] = message[i].real;
        msg_imag[i] = message[i].imag;
    }

    return SGX_SUCCESS;
}

void CKKS::polyMul(const int64_t* a, const int64_t* b, int64_t* result, uint32_t size) {
    const int64_t q = (1LL << 40);
    memset(result, 0, size * sizeof(int64_t));

    // Naive polynomial multiplication (can be optimized with NTT for production)
    for (uint32_t i = 0; i < size; i++) {
        int64_t a_i = ((a[i] % q) + q) % q;
        for (uint32_t j = 0; j < size; j++) {
            uint32_t idx = (i + j) % size;
            int64_t b_j = ((b[j] % q) + q) % q;
            int64_t prod = (a_i * b_j) % q;
            result[idx] = (result[idx] + prod) % q;
        }
    }
}

void CKKS::fft(const complex_t* input, complex_t* output, uint32_t size, bool inverse) {
    const double PI = 3.14159265358979323846;

    // Copy input to output
    memcpy(output, input, size * sizeof(complex_t));

    // Bit-reverse permutation
    uint32_t j = 0;
    for (uint32_t i = 0; i < size - 1; i++) {
        if (i < j) {
            complex_t temp = output[i];
            output[i] = output[j];
            output[j] = temp;
        }

        uint32_t mask = size >> 1;
        while (j & mask) {
            j &= ~mask;
            mask >>= 1;
        }
        j |= mask;
    }

    // Cooley-Tukey FFT algorithm
    for (uint32_t step = 2; step <= size; step <<= 1) {
        double angle = (inverse ? 2.0 : -2.0) * PI / step;
        complex_t wm = {cos(angle), sin(angle)};

        for (uint32_t i = 0; i < size; i += step) {
            complex_t w = {1.0, 0.0};

            for (uint32_t k = 0; k < step/2; k++) {
                complex_t u = output[i + k];

                // Compute t = w * output[i + k + step/2]
                complex_t t;
                t.real = w.real * output[i + k + step/2].real - w.imag * output[i + k + step/2].imag;
                t.imag = w.real * output[i + k + step/2].imag + w.imag * output[i + k + step/2].real;

                // Butterfly operation
                output[i + k].real = u.real + t.real;
                output[i + k].imag = u.imag + t.imag;

                output[i + k + step/2].real = u.real - t.real;
                output[i + k + step/2].imag = u.imag - t.imag;

                // Update w = w * wm
                double temp = w.real * wm.real - w.imag * wm.imag;
                w.imag = w.real * wm.imag + w.imag * wm.real;
                w.real = temp;
            }
        }
    }

    // Scale if inverse
    if (inverse) {
        double scale_factor = 1.0 / size;
        for (uint32_t i = 0; i < size; i++) {
            output[i].real *= scale_factor;
            output[i].imag *= scale_factor;
        }
    }
}
