#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <omp.h> // Include OpenMP for multi-core speed

const std::string BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Encodes a byte array into a Bitcoin Base58Check string
std::string EncodeBase58(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> digits(input.size() * 138 / 100 + 1, 0);
    size_t digits_len = 1;

    for (size_t i = 0; i < input.size(); i++) {
        uint32_t carry = input[i];
        for (size_t j = 0; j < digits_len; j++) {
            carry += (uint32_t)digits[j] << 8;
            digits[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits[digits_len++] = carry % 58;
            carry /= 58;
        }
    }

    std::string result = "";
    for (size_t i = 0; i < input.size() && input[i] == 0; i++) {
        result += '1';
    }
    for (size_t i = 0; i < digits_len; i++) {
        result += BASE58_CHARS[digits[digits_len - 1 - i]];
    }
    return result;
}

// Converts raw public key bytes into a Legacy (P2PKH) Bitcoin address
std::string PublicKeyToAddress(const uint8_t* pub_key, size_t len) {
    uint8_t sha256_res[SHA256_DIGEST_LENGTH];
    SHA256(pub_key, len, sha256_res);

    uint8_t ripemd_res[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_res, SHA256_DIGEST_LENGTH, ripemd_res);

    std::vector<uint8_t> address_bytes = {0x00};
    address_bytes.insert(address_bytes.end(), ripemd_res, ripemd_res + RIPEMD160_DIGEST_LENGTH);

    uint8_t check1[SHA256_DIGEST_LENGTH];
    uint8_t check2[SHA256_DIGEST_LENGTH];
    SHA256(address_bytes.data(), address_bytes.size(), check1);
    SHA256(check1, SHA256_DIGEST_LENGTH, check2);

    address_bytes.insert(address_bytes.end(), check2, check2 + 4);

    return EncodeBase58(address_bytes);
}

void IncrementPrivateKey(uint8_t* priv_key) {
    for (int i = 31; i >= 0; i--) {
        if (++priv_key[i] != 0) {
            break;
        }
    }
}

// Helper to safely convert a string to lowercase
std::string ToLower(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { 
        return std::tolower(c); 
    });
    return str;
}

int main() {
    std::string target_prefix = "1GoOdLuCk"; // Your target prefix
    std::string lower_prefix = ToLower(target_prefix);
    
    std::cout << "Targeting (Case-Insensitive): " << target_prefix << "\n";
    std::cout << "Running on " << omp_get_max_threads() << " CPU threads...\n\n";

    bool found = false;

    // OpenMP parallel region distributes work across all CPU cores
    #pragma omp parallel shared(found)
    {
        // Give each thread a unique starting private key to prevent search overlap
        int thread_num = omp_get_thread_num();
        uint8_t priv_key[32] = {
            0x4c, 0xa1, 0x1f, 0x38, 0x24, 0x22, 0x8a, 0x22,
            0x83, 0x51, 0x7b, 0x21, 0xa1, 0xd2, 0xc1, 0x54,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, (uint8_t)thread_num
        };

        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        secp256k1_pubkey pubkey;
        uint8_t compressed_pubkey[33];
        size_t len;
        uint64_t attempts = 0;

        while (!found) {
            attempts++;

            if (secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key)) {
                len = 33;
                secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);

                std::string address = PublicKeyToAddress(compressed_pubkey, len);
                
                // CRITICAL CHANGE: Convert address to lowercase for case-insensitive matching
                std::string lower_address = ToLower(address);

                // Compare lowercase versions
                if (lower_address.rfind(lower_prefix, 0) == 0) {
                    #pragma omp critical
                    {
                        if (!found) { // Double check to prevent multi-thread printing race
                            found = true;
                            std::cout << "\n[SUCCESS] Match found by Thread " << thread_num << "!\n";
                            std::cout << "Address:     " << address << "\n"; // Outputs original case mix
                            std::cout << "Private Key: ";
                            for (int i = 0; i < 32; i++) printf("%02x", priv_key[i]);
                            std::cout << "\n";
                        }
                    }
                }
            }

            IncrementPrivateKey(priv_key);

            if (thread_num == 0 && attempts % 100000 == 0) {
                std::cout << "Thread 0 checked " << attempts << " keys...\r" << std::flush;
            }
        }

        secp256k1_context_destroy(ctx);
    }

    return 0;
}
