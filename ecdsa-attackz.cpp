#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <fstream>
#include <random>
#include <sstream>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/crypto.h>

using namespace std;

// Helper to convert hex strings to OpenSSL BIGNUM
BIGNUM* hex2bn(const string& hex) {
    if (hex.empty()) return NULL;
    BIGNUM* bn = BN_new();
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

// Helper to convert hex strings to EC points
EC_POINT* hex2point(EC_GROUP* group, const string& hex) {
    if (hex.empty()) return NULL;
    EC_POINT* point = EC_POINT_new(group);
    if (EC_POINT_hex2point(group, hex.c_str(), point, NULL) == NULL) {
        EC_POINT_free(point);
        return NULL;
    }
    return point;
}

// Helper to save the private key to a file
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
// Inicjalizacja klucza publicznego z HEX
// ============================================
EC_POINT* initialize_expected_pubkey(EC_GROUP* group, const string& hex_pubkey) {
    if (!hex_pubkey.empty()) {
        EC_POINT* pub = hex2point(group, hex_pubkey);
        if (pub != nullptr) {
            cout << "✅ Pomyślnie zainicjalizowano klucz publiczny do weryfikacji." << endl;
            return pub;
        }
        cout << "⚠️ Błąd konwersji hex_pubkey. Weryfikacja kluczem pubkey będzie pominięta." << endl;
    } else {
        cout << "⚠️ Brak klucza pubkey w pliku. Weryfikacja tylko po równaniach s2." << endl;
    }
    return nullptr;
}

// ============================================
// TRYB 1: BEZPOŚREDNI WZÓR (k2 = k1 + Δ) - POPRAWNY!
// ============================================
bool try_direct_formula_with_delta(BIGNUM* r1, BIGNUM* s1, BIGNUM* z1, 
                                   BIGNUM* r2, BIGNUM* s2, BIGNUM* z2, 
                                   const BIGNUM* order, BN_CTX* ctx, BIGNUM* d, 
                                   EC_POINT* expected_pub, EC_GROUP* group, 
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
    
    BIGNUM* k1_calc = BN_new();
    BIGNUM* k2_calc = BN_new();
    BIGNUM* s2_check = BN_new();
    BIGNUM* r_d = BN_new();
    BIGNUM* temp = BN_new();

    EC_POINT* calculated_pub = EC_POINT_new(group);
    unsigned long long delta_found = 0;
    bool found = false;

    auto start = chrono::high_resolution_clock::now();

    cout << "Rozpoczynam przeszukiwanie Δ..." << endl;
    cout << "Postęp będzie wyświetlany co 1000 prób" << endl << endl;

    for (unsigned long long delta = 0; delta <= max_delta; delta++) {
        if (delta % 1000 == 0 && delta > 0) {
            auto now = chrono::high_resolution_clock::now();
            auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
            char* k1_hex = BN_bn2hex(k1_calc);
            char* k2_hex = BN_bn2hex(k2_calc);

            cout << " [Δ = " << delta << "] Czas: " << elapsed << "s" << endl;
            cout << " k1 = " << k1_hex << endl;
            cout << " k2 = " << k2_hex << endl;

            OPENSSL_free(k1_hex);
            OPENSSL_free(k2_hex);
        }

        BN_set_word(delta_bn, delta);

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

        // Sprawdź s2
        BN_mod_inverse(inv, k2_calc, order, ctx);
        BN_mod_mul(r_d, r2, d, order, ctx);
        BN_mod_add(temp, z2, r_d, order, ctx);
        BN_mod_mul(s2_check, inv, temp, order, ctx);

        bool s2_ok = (BN_cmp(s2_check, s2) == 0);

        if (s2_ok) {
            // Dogłębna weryfikacja za pomocą wczytanego klucza publicznego
            if (expected_pub != nullptr) {
                EC_POINT_mul(group, calculated_pub, d, NULL, NULL, ctx);
                if (EC_POINT_cmp(group, calculated_pub, expected_pub, ctx) == 0) {
                    delta_found = delta;
                    found = true;
                    break;
                }
            } else {
                delta_found = delta;
                found = true;
                break;
            }
        }
    }

    // Cleanup memory
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
    BN_free(s2_check);
    BN_free(r_d);
    BN_free(temp);
    EC_POINT_free(calculated_pub);

    if (found) {
        cout << "\n========================================" << endl;
        cout << "SUKCES! Znaleziono Δ = " << delta_found << endl;
        cout << "========================================" << endl;
        return true;
    } else {
        cout << "\n❌ Nie znaleziono Δ w podanym zakresie." << endl;
        return false;
    }
}

int main() {
    string filename = "signatures.txt";
    ifstream infile(filename);

    if (!infile.is_open()) {
        cerr << "❌ Błąd: Nie można otworzyć pliku " << filename << endl;
        return 1;
    }

    string hex_r1, hex_s1, hex_z1;
    string hex_r2, hex_s2, hex_z2;
    string hex_pubkey;
    string hex_order = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"; 

    string line;
    while (getline(infile, line)) {
        stringstream ss(line);
        string key, value;
        if (getline(ss, key, '=') && getline(ss, value)) {
            key.erase(key.find_last_not_of(" \n\r\t")+1);
            value.erase(0, value.find_first_not_of(" \n\r\t"));
            
            if (key == "r1") hex_r1 = value;"baf2aa695873ee637a1b23b53a78c512e4ea8ed72738badbdac3fe6b2a769176";
            else if (key == "s1") hex_s1 = value;"b47bbe4d2e405452dfa95bbd6ac3804c38c25f838edafd5ceb3456f3b040b0a6";
            else if (key == "z1") hex_z1 = value;"d20aff079cd86074eff889e1f4f0fbd0b97ef4eeff378147afc815d8a28552d5";
            else if (key == "r2") hex_r2 = value;"ceb208031cb6abc374fd0c189a9f8a5ea05f5a68baa37d665c28e52396484cef";
            else if (key == "s2") hex_s2 = value;"4c136bac45a92b2adfc0af27282b494f6dc416535433d36e04057de2bf7cc326";
            else if (key == "z2") hex_z2 = value;"17ea532a30334538c281467befb5fca7e66c6b1e760f5d17d77cb853c65a3c7d";
            else if (key == "pubkey") hex_pubkey = value;"04ee0e2a4438785f693b6d3ece91ab915f9e329c7bfa65fe68d21e8ab3ef4107d3c0d42c218d9a4f80561eb6f83a5f6644d4b47ace4adb5a123bdd287e5cfb358d";
            else if (key == "order") hex_order = value;"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        }
    }
    infile.close();

    if (hex_r1.empty() || hex_s1.empty() || hex_z1.empty() || 
        hex_r2.empty() || hex_s2.empty() || hex_z2.empty()) {
        cerr << "❌ Błąd: Brakujące parametry sygnatury w pliku." << endl;
        return 1;
    }

    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    BIGNUM* order = hex2bn(hex_order);
    BIGNUM* r1 = hex2bn(hex_r1); BIGNUM* s1 = hex2bn(hex_s1); BIGNUM* z1 = hex2bn(hex_z1);
    BIGNUM* r2 = hex2bn(hex_r2); BIGNUM* s2 = hex2bn(hex_s2); BIGNUM* z2 = hex2bn(hex_z2);
    BIGNUM* d = BN_new();

    // Wczytanie i przygotowanie klucza publicznego do weryfikacji
    EC_POINT* expected_pub = initialize_expected_pubkey(group, hex_pubkey);

    // Uruchomienie wyszukiwania
    if (try_direct_formula_with_delta(r1, s1, z1, r2, s2, z2, order, ctx, d, expected_pub, group)) {
        saveFoundKey("recovered_key.txt", d);
    }

    // Cleanup remaining OpenSSL resources
    BN_free(order);
    BN_free(r1); BN_free(s1); BN_free(z1);
    BN_free(r2); BN_free(s2); BN_free(z2);
    BN_free(d);
    if (expected_pub != nullptr) EC_POINT_free(expected_pub);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return 0;
}
