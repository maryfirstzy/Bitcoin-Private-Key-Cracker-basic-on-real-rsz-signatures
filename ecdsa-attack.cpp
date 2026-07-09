#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <fstream>
#include <random>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/crypto.h>

using namespace std;

BIGNUM* hex2bn(const string& hex) {
    BIGNUM* bn = BN_new();
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

EC_POINT* hex2point(EC_GROUP* group, const string& hex) {
    EC_POINT* point = EC_POINT_new(group);
    EC_POINT_hex2point(group, hex.c_str(), point, NULL);
    return point;
}

void saveFoundKey(const string& filename, BIGNUM* d) {
    ofstream file(filename);
    if (file.is_open()) {
        char* d_hex = BN_bn2hex(d);
        file << d_hex << endl;
        file.close();
        OPENSSL_free(d_hex);
        cout << "\n✅ Zapisano klucz do pliku: " << filename << endl;
    }
}

// ============================================
// TRYB 1: BEZPOŚREDNI WZÓR (k2 = k1 + Δ) - POPRAWNY!
// ============================================
bool try_direct_formula_with_delta(BIGNUM* r1, BIGNUM* s1, BIGNUM* z1,
                                   BIGNUM* r2, BIGNUM* s2, BIGNUM* z2,
                                   BIGNUM* r3, BIGNUM* s3, BIGNUM* z3,
                                   const BIGNUM* order, BN_CTX* ctx,
                                   BIGNUM* d, EC_POINT* expected_pub, EC_GROUP* group,
                                   unsigned long long max_delta = 10000000) {
    
    cout << "========================================" << endl;
    cout << "TRYB 1: SZUKANIE ZALEŻNOŚCI k2 = k1 + Δ" << endl;
    cout << "========================================" << endl;
    cout << "Szukam Δ od 0 do " << max_delta << endl << endl;
    
    BIGNUM* numerator = BN_new();
    BIGNUM* denominator = BN_new();
    BIGNUM* temp1 = BN_new();
    BIGNUM* temp2 = BN_new();
    BIGNUM* s1_s2 = BN_new();
    BIGNUM* delta_bn = BN_new();
    BIGNUM* inv = BN_new();
    BIGNUM* delta_times_s1_s2 = BN_new();
    
    // Do weryfikacji
    BIGNUM* k1_calc = BN_new();
    BIGNUM* k2_calc = BN_new();
    BIGNUM* k3_calc = BN_new();
    BIGNUM* s2_check = BN_new();
    BIGNUM* s3_check = BN_new();
    BIGNUM* r_d = BN_new();
    BIGNUM* k_inv = BN_new();
    BIGNUM* temp = BN_new();
    
    EC_POINT* calculated_pub = EC_POINT_new(group);
    
    unsigned long long delta_found = 0;
    bool found = false;
    auto start = chrono::high_resolution_clock::now();
    auto last_progress = start;
    
    cout << "Rozpoczynam przeszukiwanie Δ..." << endl;
    cout << "Postęp będzie wyświetlany co 1000 prób" << endl << endl;
    
    for (unsigned long long delta = 0; delta <= max_delta; delta++) {
        // Wyświetl postęp co 1000
        if (delta % 1000 == 0 && delta > 0) {
            auto now = chrono::high_resolution_clock::now();
            auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
            
            char* k1_hex = BN_bn2hex(k1_calc);
            char* k2_hex = BN_bn2hex(k2_calc);
            char* k3_hex = BN_bn2hex(k3_calc);
            
            cout << "  [Δ = " << delta << "] Czas: " << elapsed << "s" << endl;
            cout << "    k1 = " << k1_hex << endl;
            cout << "    k2 = " << k2_hex << endl;
            cout << "    k3 = " << k3_hex << endl;
            
            OPENSSL_free(k1_hex);
            OPENSSL_free(k2_hex);
            OPENSSL_free(k3_hex);
        }
        
        BN_set_word(delta_bn, delta);
        
        // ============================================
        // OBLICZ d ZE WZORU: 
        // d = (s2*z1 - s1*z2 + Δ*s1*s2) / (s1*r2 - s2*r1)
        // ============================================
        
        // Licznik: s2*z1 - s1*z2 + Δ*s1*s2
        BN_mod_mul(temp1, s2, z1, order, ctx);
        BN_mod_mul(temp2, s1, z2, order, ctx);
        BN_mod_sub(numerator, temp1, temp2, order, ctx);
        
        BN_mod_mul(s1_s2, s1, s2, order, ctx);
        BN_mod_mul(delta_times_s1_s2, delta_bn, s1_s2, order, ctx);
        BN_mod_add(numerator, numerator, delta_times_s1_s2, order, ctx);
        
        // Mianownik: s1*r2 - s2*r1
        BN_mod_mul(temp1, s1, r2, order, ctx);
        BN_mod_mul(temp2, s2, r1, order, ctx);
        BN_mod_sub(denominator, temp1, temp2, order, ctx);
        
        if (BN_is_zero(denominator)) continue;
        
        BN_mod_inverse(inv, denominator, order, ctx);
        BN_mod_mul(d, numerator, inv, order, ctx);
        
        // ============================================
        // SPRAWDŹ CZY TEN d JEST POPRAWNY
        // ============================================
        
        // Oblicz k1 = (z1 + r1*d) / s1
        BN_mod_mul(temp, r1, d, order, ctx);
        BN_mod_add(temp, z1, temp, order, ctx);
        BN_mod_inverse(inv, s1, order, ctx);
        BN_mod_mul(k1_calc, temp, inv, order, ctx);
        
        // Oblicz k2 = (z2 + r2*d) / s2
        BN_mod_mul(temp, r2, d, order, ctx);
        BN_mod_add(temp, z2, temp, order, ctx);
        BN_mod_inverse(inv, s2, order, ctx);
        BN_mod_mul(k2_calc, temp, inv, order, ctx);
        
        // Oblicz k3 = (z3 + r3*d) / s3
        BN_mod_mul(temp, r3, d, order, ctx);
        BN_mod_add(temp, z3, temp, order, ctx);
        BN_mod_inverse(inv, s3, order, ctx);
        BN_mod_mul(k3_calc, temp, inv, order, ctx);
        
        // ============================================
        // SPRAWDŹ WSZYSTKIE 3 PODPISY
        // ============================================
        
        // Sprawdź s2
        BN_mod_inverse(inv, k2_calc, order, ctx);
        BN_mod_mul(r_d, r2, d, order, ctx);
        BN_mod_add(temp, z2, r_d, order, ctx);
        BN_mod_mul(s2_check, inv, temp, order, ctx);
        
        // Sprawdź s3
        BN_mod_inverse(inv, k3_calc, order, ctx);
        BN_mod_mul(r_d, r3, d, order, ctx);
        BN_mod_add(temp, z3, r_d, order, ctx);
        BN_mod_mul(s3_check, inv, temp, order, ctx);
        
        bool s2_ok = (BN_cmp(s2_check, s2) == 0);
        bool s3_ok = (BN_cmp(s3_check, s3) == 0);
        
        // Sprawdź czy k2 = k1 + Δ
        BN_mod_sub(temp, k2_calc, k1_calc, order, ctx);
        bool delta_ok = (BN_cmp(temp, delta_bn) == 0);
        
        // ============================================
        // JAK WSZYSTKO OK - SPRAWDŹ PUBKEY
        // ============================================
        if (s2_ok && s3_ok && delta_ok) {
            EC_POINT_mul(group, calculated_pub, d, NULL, NULL, ctx);
            if (EC_POINT_cmp(group, calculated_pub, expected_pub, ctx) == 0) {
                delta_found = delta;
                found = true;
                break;
            }
        }
    }
    
    auto now = chrono::high_resolution_clock::now();
    auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
    
    if (found) {
        char* d_hex = BN_bn2hex(d);
        char* k1_hex = BN_bn2hex(k1_calc);
        char* k2_hex = BN_bn2hex(k2_calc);
        char* k3_hex = BN_bn2hex(k3_calc);
        
        cout << "\n✅ ZNALEZIONO KLUCZ BEZPOŚREDNIO!" << endl;
        cout << "   Δ = " << delta_found << " (0x" << hex << delta_found << dec << ")" << endl;
        cout << "   k1 = " << k1_hex << endl;
        cout << "   k2 = " << k2_hex << endl;
        cout << "   k3 = " << k3_hex << endl;
        cout << "   d  = " << d_hex << endl;
        cout << "   Czas: " << elapsed << "s" << endl;
        
        OPENSSL_free(d_hex);
        OPENSSL_free(k1_hex);
        OPENSSL_free(k2_hex);
        OPENSSL_free(k3_hex);
    } else {
        cout << "\n❌ Nie znaleziono Δ w zakresie 0-" << max_delta << endl;
        cout << "   Czas: " << elapsed << "s" << endl;
    }
    
    BN_free(numerator);
    BN_free(denominator);
    BN_free(temp1);
    BN_free(temp2);
    BN_free(s1_s2);
    BN_free(delta_bn);
    BN_free(inv);
    BN_free(delta_times_s1_s2);
    BN_free(k1_calc);
    BN_free(k2_calc);
    BN_free(k3_calc);
    BN_free(s2_check);
    BN_free(s3_check);
    BN_free(r_d);
    BN_free(k_inv);
    BN_free(temp);
    EC_POINT_free(calculated_pub);
    
    return found;
}
// ============================================
// TRYB 2: PRZESZUKIWANIE OD 1 W GÓRĘ
// ============================================
bool try_bruteforce(BIGNUM* r1, BIGNUM* s1, BIGNUM* z1,
                    BIGNUM* r2, BIGNUM* s2, BIGNUM* z2,
                    BIGNUM* r3, BIGNUM* s3, BIGNUM* z3,
                    const BIGNUM* order, BN_CTX* ctx,
                    BIGNUM* d, EC_POINT* expected_pub, EC_GROUP* group,
                    unsigned long long max_attempts = 1000000000) {
    
    cout << "========================================" << endl;
    cout << "TRYB 2: PRZESZUKIWANIE OD k1 = 1" << endl;
    cout << "========================================" << endl;
    cout << "Maksymalna liczba prób: " << max_attempts << endl << endl;
    
    BIGNUM* k1 = BN_new();
    BIGNUM* k2 = BN_new();
    BIGNUM* k3 = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* inv = BN_new();
    BIGNUM* one = BN_new();
    BN_one(one);
    
    BN_set_word(k1, 1);
    
    BIGNUM* r2_s1 = BN_new();
    BIGNUM* r1_s2 = BN_new();
    BIGNUM* r3_s1 = BN_new();
    BIGNUM* r1_s3 = BN_new();
    BIGNUM* r3_s2 = BN_new();
    BIGNUM* r2_s3 = BN_new();
    
    BN_mod_mul(r2_s1, r2, s1, order, ctx);
    BN_mod_mul(r1_s2, r1, s2, order, ctx);
    BN_mod_mul(r3_s1, r3, s1, order, ctx);
    BN_mod_mul(r1_s3, r1, s3, order, ctx);
    BN_mod_mul(r3_s2, r3, s2, order, ctx);
    BN_mod_mul(r2_s3, r2, s3, order, ctx);
    
    BIGNUM* RHS1 = BN_new();
    BIGNUM* RHS2 = BN_new();
    BIGNUM* RHS3 = BN_new();
    
    BN_mod_mul(temp, r2, z1, order, ctx);
    BN_mod_mul(inv, r1, z2, order, ctx);
    BN_mod_sub(RHS1, temp, inv, order, ctx);
    
    BN_mod_mul(temp, r3, z1, order, ctx);
    BN_mod_mul(inv, r1, z3, order, ctx);
    BN_mod_sub(RHS2, temp, inv, order, ctx);
    
    BN_mod_mul(temp, r3, z2, order, ctx);
    BN_mod_mul(inv, r2, z3, order, ctx);
    BN_mod_sub(RHS3, temp, inv, order, ctx);
    
    BIGNUM* s2_check = BN_new();
    BIGNUM* s3_check = BN_new();
    BIGNUM* r_d = BN_new();
    BIGNUM* k_inv = BN_new();
    EC_POINT* calculated_pub = EC_POINT_new(group);
    
    unsigned long long attempts = 0;
    unsigned long long solutions_found = 0;
    auto start = chrono::high_resolution_clock::now();
    auto last_progress = start;
    bool found = false;
    
    cout << "Rozpoczynam przeszukiwanie od k1 = 1..." << endl;
    cout << "Postęp będzie wyświetlany co 1000 prób" << endl << endl;
    
    while (attempts < max_attempts) {
        attempts++;
        
        // Wyświetl postęp co 1000
        if (attempts % 1000 == 0) {
            auto now = chrono::high_resolution_clock::now();
            auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
            char* k1_hex = BN_bn2hex(k1);
            
            cout << "  [k1 = " << k1_hex << "] Czas: " << elapsed << "s | Rozwiązania: " << solutions_found << endl;
            
            OPENSSL_free(k1_hex);
        }
        
        BN_mod_mul(temp, r2_s1, k1, order, ctx);
        BN_mod_sub(temp, temp, RHS1, order, ctx);
        BN_mod_inverse(inv, r1_s2, order, ctx);
        BN_mod_mul(k2, temp, inv, order, ctx);
        
        BN_mod_mul(temp, r3_s1, k1, order, ctx);
        BN_mod_sub(temp, temp, RHS2, order, ctx);
        BN_mod_inverse(inv, r1_s3, order, ctx);
        BN_mod_mul(k3, temp, inv, order, ctx);
        
        BN_mod_mul(temp, r3_s2, k2, order, ctx);
        BN_mod_mul(inv, r2_s3, k3, order, ctx);
        BN_mod_sub(temp, temp, inv, order, ctx);
        bool eq3_ok = (BN_cmp(temp, RHS3) == 0);
        
        if (eq3_ok) {
            BN_mod_mul(temp, s1, k1, order, ctx);
            BN_mod_sub(temp, temp, z1, order, ctx);
            BN_mod_inverse(inv, r1, order, ctx);
            BN_mod_mul(d, temp, inv, order, ctx);
            
            BN_mod_inverse(inv, k2, order, ctx);
            BN_mod_mul(r_d, r2, d, order, ctx);
            BN_mod_add(temp, z2, r_d, order, ctx);
            BN_mod_mul(s2_check, inv, temp, order, ctx);
            
            BN_mod_inverse(inv, k3, order, ctx);
            BN_mod_mul(r_d, r3, d, order, ctx);
            BN_mod_add(temp, z3, r_d, order, ctx);
            BN_mod_mul(s3_check, inv, temp, order, ctx);
            
            bool s2_ok = (BN_cmp(s2_check, s2) == 0);
            bool s3_ok = (BN_cmp(s3_check, s3) == 0);
            
            if (s2_ok && s3_ok) {
                solutions_found++;
                EC_POINT_mul(group, calculated_pub, d, NULL, NULL, ctx);
                if (EC_POINT_cmp(group, calculated_pub, expected_pub, ctx) == 0) {
                    found = true;
                    break;
                }
            }
        }
        
        BN_add(k1, k1, one);
    }
    
    auto now = chrono::high_resolution_clock::now();
    auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
    
    if (found) {
        char* d_hex = BN_bn2hex(d);
        char* k1_hex = BN_bn2hex(k1);
        cout << "\n✅ ZNALEZIONO KLUCZ PRZEZ PRZESZUKIWANIE!" << endl;
        cout << "   k1 = " << k1_hex << endl;
        cout << "   d = " << d_hex << endl;
        cout << "   Próby: " << attempts << endl;
        cout << "   Czas: " << elapsed << "s" << endl;
        OPENSSL_free(d_hex);
        OPENSSL_free(k1_hex);
    } else {
        cout << "\n❌ Nie znaleziono w " << attempts << " próbach" << endl;
        cout << "   Czas: " << elapsed << "s" << endl;
    }
    
    BN_free(k1); BN_free(k2); BN_free(k3);
    BN_free(temp); BN_free(inv); BN_free(one);
    BN_free(r2_s1); BN_free(r1_s2); BN_free(r3_s1);
    BN_free(r1_s3); BN_free(r3_s2); BN_free(r2_s3);
    BN_free(RHS1); BN_free(RHS2); BN_free(RHS3);
    BN_free(s2_check); BN_free(s3_check);
    BN_free(r_d); BN_free(k_inv);
    EC_POINT_free(calculated_pub);
    
    return found;
}

// ============================================
// TRYB 3: LOSOWE k1
// ============================================
bool try_random(BIGNUM* r1, BIGNUM* s1, BIGNUM* z1,
                BIGNUM* r2, BIGNUM* s2, BIGNUM* z2,
                BIGNUM* r3, BIGNUM* s3, BIGNUM* z3,
                const BIGNUM* order, BN_CTX* ctx,
                BIGNUM* d, EC_POINT* expected_pub, EC_GROUP* group,
                unsigned long long max_attempts = 10000000) {
    
    cout << "========================================" << endl;
    cout << "TRYB 3: LOSOWE k1" << endl;
    cout << "========================================" << endl;
    cout << "Maksymalna liczba prób: " << max_attempts << endl << endl;
    
    random_device rd_device;
    mt19937_64 gen(rd_device());
    uniform_int_distribution<unsigned long long> dis(1, 0xFFFFFFFFFFFFFFFFULL);
    
    BIGNUM* k1 = BN_new();
    BIGNUM* k2 = BN_new();
    BIGNUM* k3 = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* inv = BN_new();
    
    BIGNUM* r2_s1 = BN_new();
    BIGNUM* r1_s2 = BN_new();
    BIGNUM* r3_s1 = BN_new();
    BIGNUM* r1_s3 = BN_new();
    BIGNUM* r3_s2 = BN_new();
    BIGNUM* r2_s3 = BN_new();
    
    BN_mod_mul(r2_s1, r2, s1, order, ctx);
    BN_mod_mul(r1_s2, r1, s2, order, ctx);
    BN_mod_mul(r3_s1, r3, s1, order, ctx);
    BN_mod_mul(r1_s3, r1, s3, order, ctx);
    BN_mod_mul(r3_s2, r3, s2, order, ctx);
    BN_mod_mul(r2_s3, r2, s3, order, ctx);
    
    BIGNUM* RHS1 = BN_new();
    BIGNUM* RHS2 = BN_new();
    BIGNUM* RHS3 = BN_new();
    
    BN_mod_mul(temp, r2, z1, order, ctx);
    BN_mod_mul(inv, r1, z2, order, ctx);
    BN_mod_sub(RHS1, temp, inv, order, ctx);
    
    BN_mod_mul(temp, r3, z1, order, ctx);
    BN_mod_mul(inv, r1, z3, order, ctx);
    BN_mod_sub(RHS2, temp, inv, order, ctx);
    
    BN_mod_mul(temp, r3, z2, order, ctx);
    BN_mod_mul(inv, r2, z3, order, ctx);
    BN_mod_sub(RHS3, temp, inv, order, ctx);
    
    BIGNUM* s2_check = BN_new();
    BIGNUM* s3_check = BN_new();
    BIGNUM* r_d = BN_new();
    BIGNUM* k_inv = BN_new();
    EC_POINT* calculated_pub = EC_POINT_new(group);
    
    unsigned long long attempts = 0;
    unsigned long long solutions_found = 0;
    auto start = chrono::high_resolution_clock::now();
    auto last_progress = start;
    bool found = false;
    
    cout << "Rozpoczynam losowe przeszukiwanie..." << endl;
    cout << "Postęp będzie wyświetlany co 1000 prób" << endl << endl;
    
    while (attempts < max_attempts) {
        attempts++;
        
        if (attempts % 1000 == 0) {
            auto now = chrono::high_resolution_clock::now();
            auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
            char* k1_hex = BN_bn2hex(k1);
            
            cout << "  [Próba " << attempts << "] k1 = " << k1_hex << " | Czas: " << elapsed << "s" << endl;
            
            OPENSSL_free(k1_hex);
        }
        
        unsigned long long rand_val = dis(gen);
        BN_set_word(k1, rand_val);
        if (BN_is_zero(k1)) continue;
        
        BN_mod_mul(temp, r2_s1, k1, order, ctx);
        BN_mod_sub(temp, temp, RHS1, order, ctx);
        BN_mod_inverse(inv, r1_s2, order, ctx);
        BN_mod_mul(k2, temp, inv, order, ctx);
        
        BN_mod_mul(temp, r3_s1, k1, order, ctx);
        BN_mod_sub(temp, temp, RHS2, order, ctx);
        BN_mod_inverse(inv, r1_s3, order, ctx);
        BN_mod_mul(k3, temp, inv, order, ctx);
        
        BN_mod_mul(temp, r3_s2, k2, order, ctx);
        BN_mod_mul(inv, r2_s3, k3, order, ctx);
        BN_mod_sub(temp, temp, inv, order, ctx);
        bool eq3_ok = (BN_cmp(temp, RHS3) == 0);
        
        if (eq3_ok) {
            BN_mod_mul(temp, s1, k1, order, ctx);
            BN_mod_sub(temp, temp, z1, order, ctx);
            BN_mod_inverse(inv, r1, order, ctx);
            BN_mod_mul(d, temp, inv, order, ctx);
            
            BN_mod_inverse(inv, k2, order, ctx);
            BN_mod_mul(r_d, r2, d, order, ctx);
            BN_mod_add(temp, z2, r_d, order, ctx);
            BN_mod_mul(s2_check, inv, temp, order, ctx);
            
            BN_mod_inverse(inv, k3, order, ctx);
            BN_mod_mul(r_d, r3, d, order, ctx);
            BN_mod_add(temp, z3, r_d, order, ctx);
            BN_mod_mul(s3_check, inv, temp, order, ctx);
            
            bool s2_ok = (BN_cmp(s2_check, s2) == 0);
            bool s3_ok = (BN_cmp(s3_check, s3) == 0);
            
            if (s2_ok && s3_ok) {
                solutions_found++;
                EC_POINT_mul(group, calculated_pub, d, NULL, NULL, ctx);
                if (EC_POINT_cmp(group, calculated_pub, expected_pub, ctx) == 0) {
                    found = true;
                    break;
                }
            }
        }
    }
    
    auto now = chrono::high_resolution_clock::now();
    auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
    
    if (found) {
        char* d_hex = BN_bn2hex(d);
        char* k1_hex = BN_bn2hex(k1);
        cout << "\n✅ ZNALEZIONO KLUCZ LOSOWO!" << endl;
        cout << "   k1 = " << k1_hex << endl;
        cout << "   d = " << d_hex << endl;
        cout << "   Próby: " << attempts << endl;
        cout << "   Czas: " << elapsed << "s" << endl;
        OPENSSL_free(d_hex);
        OPENSSL_free(k1_hex);
    } else {
        cout << "\n❌ Nie znaleziono w " << attempts << " losowych próbach" << endl;
        cout << "   Czas: " << elapsed << "s" << endl;
    }
    
    BN_free(k1); BN_free(k2); BN_free(k3);
    BN_free(temp); BN_free(inv);
    BN_free(r2_s1); BN_free(r1_s2); BN_free(r3_s1);
    BN_free(r1_s3); BN_free(r3_s2); BN_free(r2_s3);
    BN_free(RHS1); BN_free(RHS2); BN_free(RHS3);
    BN_free(s2_check); BN_free(s3_check);
    BN_free(r_d); BN_free(k_inv);
    EC_POINT_free(calculated_pub);
    
    return found;
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    const BIGNUM* order = EC_GROUP_get0_order(group);
    BN_CTX* ctx = BN_CTX_new();

    // ============================================
    // DANE TESTOWE
    // ============================================
    string pubkey_hex = "04ee0e2a4438785f693b6d3ece91ab915f9e329c7bfa65fe68d21e8ab3ef4107d3c0d42c218d9a4f80561eb6f83a5f6644d4b47ace4adb5a123bdd287e5cfb358d";
    EC_POINT* expected_pub = hex2point(group, pubkey_hex);

    // ============================================
    // PODPIS 1
    // ============================================
string r1_hex = "baf2aa695873ee637a1b23b53a78c512e4ea8ed72738badbdac3fe6b2a769176";
string s1_hex = "b47bbe4d2e405452dfa95bbd6ac3804c38c25f838edafd5ceb3456f3b040b0a6";
string z1_hex = "d20aff079cd86074eff889e1f4f0fbd0b97ef4eeff378147afc815d8a28552d5";

    // ============================================
    // PODPIS 2
    // ============================================
string r2_hex = "d56a07721d620e6b3c64021713ae2cec9bc831c4d6d32501e347142bff70d078";
string s2_hex = "4c136bac45a92b2adfc0af27282b494f6dc416535433d36e04057de2bf7cc326";
string z2_hex = "17ea532a30334538c281467befb5fca7e66c6b1e760f5d17d77cb853c65a3c7d";

    // ============================================
    // PODPIS 3
    // ============================================
string r3_hex = "ceb208031cb6abc374fd0c189a9f8a5ea05f5a68baa37d665c28e52396484cef";
string s3_hex = "f7f3b63279f4ee697783fe49e0d0b91c20264f96fabe1623bd9a61cbb66cefad";
string z3_hex = "da7044deeac4a5873a8fee74de8fcffd9e8fde51b67b38ab0293ae17e5d3c405";


    BIGNUM* r1 = hex2bn(r1_hex);
    BIGNUM* s1 = hex2bn(s1_hex);
    BIGNUM* z1 = hex2bn(z1_hex);
    BIGNUM* r2 = hex2bn(r2_hex);
    BIGNUM* s2 = hex2bn(s2_hex);
    BIGNUM* z2 = hex2bn(z2_hex);
    BIGNUM* r3 = hex2bn(r3_hex);
    BIGNUM* s3 = hex2bn(s3_hex);
    BIGNUM* z3 = hex2bn(z3_hex);

    cout << "========================================" << endl;
    cout << "SZUKANIE Z 3 PODPISAMI - 3 TRYBY" << endl;
    cout << "========================================" << endl;
    cout << "Szukam pubkey: " << pubkey_hex << endl << endl;
    cout << "Dane wejściowe:" << endl;
    cout << "  Podpis 1: r1 = " << r1_hex.substr(0, 16) << "... s1 = " << s1_hex.substr(0, 16) << "..." << endl;
    cout << "  Podpis 2: r2 = " << r2_hex.substr(0, 16) << "... s2 = " << s2_hex.substr(0, 16) << "..." << endl;
    cout << "  Podpis 3: r3 = " << r3_hex.substr(0, 16) << "... s3 = " << s3_hex.substr(0, 16) << "..." << endl;
    cout << endl;

    BIGNUM* d = BN_new();
    bool found = false;

    // ============================================
    // TRYB 1: BEZPOŚREDNI WZÓR (k2 = k1 + Δ) z weryfikacją 3 podpisów
    // ============================================
    cout << "\n" << string(70, '=') << endl;
    found = try_direct_formula_with_delta(r1, s1, z1, r2, s2, z2, r3, s3, z3,
                                          order, ctx, d, expected_pub, group, 10000000);
    if (found) {
        saveFoundKey("found_private_key_direct.txt", d);
        goto cleanup;
    }

    // ============================================
    // TRYB 2: PRZESZUKIWANIE
    // ============================================
    cout << "\n" << string(70, '=') << endl;
    found = try_bruteforce(r1, s1, z1, r2, s2, z2, r3, s3, z3,
                           order, ctx, d, expected_pub, group, 1000000000);
    if (found) {
        saveFoundKey("found_private_key_bruteforce.txt", d);
        goto cleanup;
    }

    // ============================================
    // TRYB 3: LOSOWE
    // ============================================
    cout << "\n" << string(70, '=') << endl;
    found = try_random(r1, s1, z1, r2, s2, z2, r3, s3, z3,
                       order, ctx, d, expected_pub, group, 10000000);
    if (found) {
        saveFoundKey("found_private_key_random.txt", d);
        goto cleanup;
    }

    cout << "\n❌ NIE ZNALEZIONO KLUCZA ŻADNYM TRYBEM!" << endl;

cleanup:
    BN_free(r1); BN_free(s1); BN_free(z1);
    BN_free(r2); BN_free(s2); BN_free(z2);
    BN_free(r3); BN_free(s3); BN_free(z3);
    BN_free(d);
    EC_POINT_free(expected_pub);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 0;
}
