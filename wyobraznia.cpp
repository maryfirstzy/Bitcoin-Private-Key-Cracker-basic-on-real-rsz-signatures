#include <iostream>
#include <iomanip>
#include <string>
#include <random>
#include <chrono>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/crypto.h>

using namespace std;

// Konwersja hex string na BIGNUM
BIGNUM* hex2bn(const string& hex) {
    BIGNUM* bn = BN_new();
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

// Konwersja hex string na EC_POINT
EC_POINT* hex2point(EC_GROUP* group, const string& hex) {
    EC_POINT* point = EC_POINT_new(group);
    EC_POINT_hex2point(group, hex.c_str(), point, NULL);
    return point;
}

int main() {
    // Inicjalizacja OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

    // Krzywa secp256k1
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    const BIGNUM* order = EC_GROUP_get0_order(group);
    BN_CTX* ctx = BN_CTX_new();

    // Oczekiwany pubkey
    string pubkey_hex = "04766671d3b6d67717b38a4ef1653ad2e39e695a70d535e996b0825635698fa2338d5d81be10736c67f61aabc6d260caaf65ec8bc6b8ae7b14604cab07665e8db1";
    EC_POINT* expected_pub = hex2point(group, pubkey_hex);

    // Dane z podpisów
    string r1_hex = "c332d7827cbb67ac0604037418d75e3890571749f564ee2ecfaf9d511b92d099";
    string s1_hex = "acf1fecf54ce3d5cda0ce782ca886b6665da471bf7b34a604ae360733ea10b3e";
    string z1_hex = "3388aa043fbf22d3d8d9d1f0c214ced381374f73979e3f7dd8bc2f04c22d350f";

    string r2_hex = "0365deb19bbc43af9775ef673ed4da6277b0c5f527f134f7b1dc6bd3b82b1fe3";
    string s2_hex = "7818845c8536f8a29d960fa5a3dffb25936423fedeae8e35eea9b55aed80388c";
    string z2_hex = "8918b7af591ee31f55521b051658f33531ff5aa5c8b4d69df3e5a9be0a9ca929";

    BIGNUM* r1 = hex2bn(r1_hex);
    BIGNUM* s1 = hex2bn(s1_hex);
    BIGNUM* z1 = hex2bn(z1_hex);
    BIGNUM* r2 = hex2bn(r2_hex);
    BIGNUM* s2 = hex2bn(s2_hex);
    BIGNUM* z2 = hex2bn(z2_hex);

    BIGNUM* k1 = BN_new();
    BIGNUM* k2 = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* r_inv = BN_new();
    BIGNUM* k_inv = BN_new();

    // Zmienne do sprawdzania
    BIGNUM* s2_check = BN_new();
    BIGNUM* rd = BN_new();

    // Zmienne do weryfikacji pubkey
    EC_POINT* calculated_pub = EC_POINT_new(group);

    // Zmienne dla Twoich równań
    BIGNUM* left_side = BN_new();   // s1*k1 - s2*k2
    BIGNUM* right_side = BN_new();  // z1 - z2 + d*(r1 - r2)
    BIGNUM* r1_minus_r2 = BN_new();
    BIGNUM* z1_minus_z2 = BN_new();
    BIGNUM* s1k1 = BN_new();
    BIGNUM* s2k2 = BN_new();

    unsigned long long attempts = 0;
    unsigned long long solutions_found = 0;
    auto start = chrono::high_resolution_clock::now();
    auto last_progress = start;

    cout << "========================================" << endl;
    cout << "SZUKANIE KLUCZA PRYWATNEGO" << endl;
    cout << "========================================" << endl;
    cout << "Równania ECDSA:" << endl;
    cout << "  s1 = k1^(-1) * (z1 + r1*d) mod n" << endl;
    cout << "  s2 = k2^(-1) * (z2 + r2*d) mod n" << endl << endl;
    
    cout << "Twoje przekształcenia:" << endl;
    cout << "  1. Odejmowanie równań:" << endl;
    cout << "     s1*k1 - s2*k2 = z1 - z2 + d*(r1 - r2)" << endl << endl;
    
    cout << "  2. Eliminacja d:" << endl;
    cout << "     (s1*k1 - z1)/r1 = (s2*k2 - z2)/r2" << endl << endl;
    
    cout << "Szukam pubkey: " << pubkey_hex << endl << endl;
    cout << "========================================" << endl << endl;

    while (true) {
        attempts++;

        // Losowe k1 z przedziału [1, n-1]
        BN_rand_range(k1, order);
        if (BN_is_zero(k1)) continue;

        // ============================================
        // Oblicz d z pierwszego równania:
        // d = (s1*k1 - z1) / r1 mod n
        // ============================================
        BN_mod_mul(temp, s1, k1, order, ctx);
        BN_mod_sub(temp, temp, z1, order, ctx);
        BN_mod_inverse(r_inv, r1, order, ctx);
        BN_mod_mul(d, temp, r_inv, order, ctx);

        // ============================================
        // Oblicz k2 z drugiego równania:
        // k2 = (z2 + r2*d) / s2 mod n
        // ============================================
        BN_mod_mul(rd, r2, d, order, ctx);
        BN_mod_add(temp, z2, rd, order, ctx);
        BN_mod_inverse(k_inv, s2, order, ctx);
        BN_mod_mul(k2, temp, k_inv, order, ctx);

        // ============================================
        // Sprawdzenie poprawności: obliczamy s2 z powrotem
        // s2_check = k2^(-1) * (z2 + r2*d) mod n
        // ============================================
        BN_mod_inverse(k_inv, k2, order, ctx);
        BN_mod_mul(rd, r2, d, order, ctx);
        BN_mod_add(temp, z2, rd, order, ctx);
        BN_mod_mul(s2_check, k_inv, temp, order, ctx);

        // ============================================
        // SPRAWDZAMY TWOJE RÓWNANIA!
        // ============================================
        
        // Równanie 1: s1*k1 - s2*k2 = z1 - z2 + d*(r1 - r2)
        BN_mod_mul(s1k1, s1, k1, order, ctx);
        BN_mod_mul(s2k2, s2, k2, order, ctx);
        BN_mod_sub(left_side, s1k1, s2k2, order, ctx);
        
        BN_mod_sub(z1_minus_z2, z1, z2, order, ctx);
        BN_mod_sub(r1_minus_r2, r1, r2, order, ctx);
        BN_mod_mul(rd, d, r1_minus_r2, order, ctx);
        BN_mod_add(right_side, z1_minus_z2, rd, order, ctx);
        
        bool eq1_ok = (BN_cmp(left_side, right_side) == 0);
        
        // Równanie 2: (s1*k1 - z1)/r1 = (s2*k2 - z2)/r2
        // Czyli: r2*(s1*k1 - z1) = r1*(s2*k2 - z2)
        BIGNUM* eq2_left = BN_new();
        BIGNUM* eq2_right = BN_new();
        BIGNUM* s1k1_minus_z1 = BN_new();
        BIGNUM* s2k2_minus_z2 = BN_new();
        
        BN_mod_sub(s1k1_minus_z1, s1k1, z1, order, ctx);
        BN_mod_sub(s2k2_minus_z2, s2k2, z2, order, ctx);
        BN_mod_mul(eq2_left, r2, s1k1_minus_z1, order, ctx);
        BN_mod_mul(eq2_right, r1, s2k2_minus_z2, order, ctx);
        
        bool eq2_ok = (BN_cmp(eq2_left, eq2_right) == 0);
        
        BN_free(eq2_left);
        BN_free(eq2_right);
        BN_free(s1k1_minus_z1);
        BN_free(s2k2_minus_z2);

        // Porównujemy s2_check z s2
        if (BN_cmp(s2_check, s2) == 0) {
            solutions_found++;
            
            // Sprawdzamy, czy d generuje poprawny pubkey
            EC_POINT_mul(group, calculated_pub, d, NULL, NULL, ctx);

            if (EC_POINT_cmp(group, calculated_pub, expected_pub, ctx) == 0) {
                // ZNALEZIONO PRAWDZIWY KLUCZ!
                auto now = chrono::high_resolution_clock::now();
                auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();

                cout << "\n**************************************************" << endl;
                cout << "*** ZNALEZIONO PRAWDZIWY KLUCZ PRYWATNY! ***" << endl;
                cout << "**************************************************" << endl;
                cout << "Czas: " << elapsed << "s" << endl;
                cout << "Próby (k1): " << attempts << endl;
                cout << "Rozwiązania matematyczne: " << solutions_found << endl;

                char* d_hex = BN_bn2hex(d);
                char* k1_hex = BN_bn2hex(k1);
                char* k2_hex = BN_bn2hex(k2);

                cout << "d (klucz prywatny): " << d_hex << endl;
                cout << "k1 (nonce dla 1. podpisu): " << k1_hex << endl;
                cout << "k2 (nonce dla 2. podpisu): " << k2_hex << endl;

                cout << "\nTwoje równania dla znalezionego rozwiązania:" << endl;
                cout << "  s1*k1 - s2*k2 = z1 - z2 + d*(r1 - r2)  " << (eq1_ok ? "✅ OK" : "❌ BŁĄD") << endl;
                cout << "  (s1*k1 - z1)/r1 = (s2*k2 - z2)/r2      " << (eq2_ok ? "✅ OK" : "❌ BŁĄD") << endl;

                OPENSSL_free(d_hex);
                OPENSSL_free(k1_hex);
                OPENSSL_free(k2_hex);

                break;
            } else {
                // Co 1000 rozwiązań pokazujemy informację
                if (solutions_found % 1000 == 0) {
                    char* d_hex = BN_bn2hex(d);
                    char* k1_hex = BN_bn2hex(k1);
                    char* k2_hex = BN_bn2hex(k2);
                    auto now = chrono::high_resolution_clock::now();
                    auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
                    
                    cout << "[#" << solutions_found << "] Próby: " << attempts 
                         << " | Czas: " << elapsed << "s" << endl;
                    cout << "  d = " << d_hex << " (nie pasuje do pubkey)" << endl;
                    cout << "  k1 = " << k1_hex << endl;
                    cout << "  k2 = " << k2_hex << endl;
                    cout << "  Równanie 1: " << (eq1_ok ? "✅ OK" : "❌ BŁĄD") << endl;
                    cout << "  Równanie 2: " << (eq2_ok ? "✅ OK" : "❌ BŁĄD") << endl << endl;
                    
                    OPENSSL_free(d_hex);
                    OPENSSL_free(k1_hex);
                    OPENSSL_free(k2_hex);
                }
                continue;
            }
        }

        // Pokazujemy postęp co 1 milion prób
        if (attempts % 1000000 == 0) {
            auto now = chrono::high_resolution_clock::now();
            auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
            auto diff = chrono::duration_cast<chrono::seconds>(now - last_progress).count();
            
            double speed = 1000000.0 / (diff > 0 ? diff : 1);
            
            cout << "\n[STATUS] Próby: " << attempts 
                 << " | Rozwiązań: " << solutions_found 
                 << " | Czas: " << elapsed << "s" 
                 << " | Szybkość: " << fixed << setprecision(0) << speed << " k1/s" << endl << endl;
            
            last_progress = now;
        }
    }

    // Czyszczenie
    BN_free(k1);
    BN_free(k2);
    BN_free(d);
    BN_free(temp);
    BN_free(r_inv);
    BN_free(k_inv);
    BN_free(s2_check);
    BN_free(rd);
    BN_free(r1);
    BN_free(s1);
    BN_free(z1);
    BN_free(r2);
    BN_free(s2);
    BN_free(z2);
    BN_free(left_side);
    BN_free(right_side);
    BN_free(r1_minus_r2);
    BN_free(z1_minus_z2);
    BN_free(s1k1);
    BN_free(s2k2);
    EC_POINT_free(calculated_pub);
    EC_POINT_free(expected_pub);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 0;
}
