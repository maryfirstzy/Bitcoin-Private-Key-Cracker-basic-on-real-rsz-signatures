🔐 ECDSA Nonce Attack Suite - 3 Signature Recovery
https://img.shields.io/badge/License-MIT-yellow.svg
https://img.shields.io/badge/C++-11-blue.svg
https://img.shields.io/badge/OpenSSL-3.0-green.svg

📝 Description
A comprehensive ECDSA private key recovery tool that exploits vulnerabilities in nonce (k) generation. The program implements three distinct attack methods to recover the private key from the secp256k1 curve using three ECDSA signatures.

🎯 Goal
Recover the private key (d) from the secp256k1 curve using three ECDSA signatures that potentially have weak, predictable, or related nonces (k values).

🔬 Methodology
Mathematical Foundation
For ECDSA signatures we have the following system of equations:

text
s1 = (z1 + r1*d) / k1  (mod n)
s2 = (z2 + r2*d) / k2  (mod n)
s3 = (z3 + r3*d) / k3  (mod n)
Where:

s - signature component

z - message hash (transaction hash)

r - signature component (x-coordinate of k*G point)

d - private key (target)

k - nonce (ephemeral key, must be random)

n - curve order (secp256k1)

⚡ Three Attack Methods
Method 1: Direct Formula (k₂ = k₁ + Δ)
This method searches for a linear relationship between nonces: k₂ = k₁ + Δ.

Mathematical Derivation:

When k₂ = k₁ + Δ, we can derive:

text
d = (s₂*z₁ - s₁*z₂ + Δ*s₁*s₂) / (s₁*r₂ - s₂*r₁)  (mod n)
The algorithm:

Iterates Δ from 0 to max_delta (default: 10,000,000)

For each Δ, calculates d using the formula

Verifies all three signatures match

Checks if k₂ = k₁ + Δ holds

Validates the public key

⚠️ Important: This method requires UNNORMALIZED s values (low-s normalization breaks the formula).

Use Case: When nonces are generated with a known linear relationship (e.g., counter-based RNG).

Method 2: Brute Force (k₁ from 1 upwards)
This method searches for k₁ by brute force, starting from 1.

Algorithm:

For each k₁ from 1 to max_attempts:

Calculates k₂ and k₃ from the system of equations

Verifies all three signatures match

Checks the public key

Stops when the correct private key is found

Use Case: When k₁ is small (weak RNG, low entropy, or buggy implementation).

Method 3: Random Search (Random k₁)
This method generates random k₁ values and tests them.

Algorithm:

Generates random 64-bit k₁ values

For each random k₁:

Calculates k₂ and k₃ from the system

Verifies all three signatures match

Checks the public key

Stops when the correct private key is found

Use Case: When k₁ is large but you want to try random guesses (similar to lottery).

📊 Performance
Method	Speed	Success Condition
Method 1	< 1 second	Known linear relationship k₂ = k₁ + Δ
Method 2	~4000 k₁/s	Small k₁ (< 1,000,000)
Method 3	~4000 attempts/s	Lucky random guess
🚀 Installation & Usage
Requirements
bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install libssl-dev build-essential

# macOS
brew install openssl

# Arch Linux
sudo pacman -S openssl base-devel
Compilation
bash
# Basic compilation
g++ -std=c++11 -O2 -o ecdsa-attack ecdsa-attack.cpp -lssl -lcrypto

# With optimizations
g++ -std=c++11 -O3 -march=native -o ecdsa-attack ecdsa-attack.cpp -lssl -lcrypto
Usage
Replace the test data in main() with your signatures:

cpp
string pubkey_hex = "04...";
string r1_hex = "...", s1_hex = "...", z1_hex = "...";
string r2_hex = "...", s2_hex = "...", z2_hex = "...";
string r3_hex = "...", s3_hex = "...", z3_hex = "...";
Compile and run:

bash
g++ -std=c++11 -O2 ecdsa-attack.cpp -o ecdsa-attack -lssl -lcrypto
./ecdsa-attack
📁 Output Files
File	Description
found_private_key_direct.txt	Key found via Method 1
found_private_key_bruteforce.txt	Key found via Method 2
found_private_key_random.txt	Key found via Method 3
🔬 Test Cases
Test Case 1: Linear Relationship (Method 1)
python
k1 = 0x12345
k2 = k1 + 0x100  # Δ = 256
k3 = k1 + 0x200  # Δ = 512
Important: s values must be UNNORMALIZED!

python
# DO NOT normalize s!
s = ((z + r * d) * inverse_mod(k, order)) % order
# if s > order // 2:
#     s = order - s  # <- DON'T DO THIS!
Test Case 2: Small k₁ (Method 2)
python
k1 = 0x12345  # Small value
k2 = random  # Any value
k3 = random  # Any value
Test Case 3: Random Search (Method 3)
python
k1 = random large  # 64-bit random
k2 = random
k3 = random
🧪 Example Output
text
========================================
SEARCHING WITH 3 SIGNATURES - 3 MODES
========================================
Looking for pubkey: 04f9ca894225446120bec36db4819cac...

Input data:
  Signature 1: r1 = e963ffdf... s1 = 389c5839...
  Signature 2: r2 = 077be39f... s2 = 29254b4c...
  Signature 3: r3 = c4b9ba86... s3 = 578a8a4b...

======================================================================
========================================
MODE 1: SEARCHING FOR k2 = k1 + Δ
========================================
Searching Δ from 0 to 10000000

Starting Δ search...
Progress shown every 1000 attempts

  [Δ = 1000] Time: 0s
    k1 = 651867A0...
    k2 = 651867A0...
    k3 = 16274497...

✅ KEY FOUND DIRECTLY!
   Δ = 256 (0x100)
   k1 = 0000000000000000000000000000000000000000000000000000000000012345
   k2 = 0000000000000000000000000000000000000000000000000000000000012445
   k3 = 0000000000000000000000000000000000000000000000000000000000012545
   d  = DDD7D19C659AE145E1F15A6F6D3B0F5A8EED6B35353CFAE93258A0E3D9CD77C1
   Time: 0s

✅ Key saved to file: found_private_key_direct.txt
🎯 Real-World Scenarios
This attack can be successful in cases like:

PS3 Private Key Hack (2010) - Sony used the same k for all signatures

Bitcoin Transaction Reuse Attacks - Nonce reuse in transactions

Android RNG Bug - Poor entropy in random number generator

Weak RNG Implementations - Nonces from time or small seed values

Counter-based Nonces - k₂ = k₁ + 1 type relationships

⚠️ Important Notes
Normalization Matters!
Method 1 requires UNNORMALIZED s values (low-s normalization breaks the formula)

Methods 2 and 3 work with BOTH normalized and unnormalized s

Bitcoin and most cryptocurrencies use low-s normalization

Runtime
Method 1: < 1 second (if relationship exists)

Method 2: Depends on k₁ size (~1 second per 4000 attempts)

Method 3: Probabilistic, no guaranteed time

Hardware Requirements
Memory: < 100 MB

CPU: Faster = better

Multi-threading: Not currently implemented (future feature)

📚 References
RFC 6979 - Deterministic ECDSA

SEC 2: Recommended Elliptic Curve Domain Parameters

ECDSA Nonce Reuse Attack

Bitcoin Nonce Reuse Statistics

📝 License
MIT License - for educational use only

⚠️ WARNING
This program is for educational purposes only. Do not use it to attack real systems or steal cryptocurrencies. Understanding these vulnerabilities is crucial for building more secure systems.

🧪 Generator Script
Use the included Python script to generate test cases:

python
python3 generate_test.py
This creates test data with:

Known linear relationships (for Method 1)

Small nonces (for Method 2)

Various test scenarios

Made for educational purposes. Use responsibly. 🔐

python
python3 generate_test.py
This will create:
============================================================
WY GENEROWANE DANE TESTOWE
============================================================

(venv) daro@mojkomputer:/mnt/c/Users/opini/Desktop/ALLKRYPTO/BreakingECDSAwithLLL$ python3 testpodpisy.py
string pubkey_hex = "04f9ca894225446120bec36db4819cac96417e3590d1e6c7c8b70d2edf4c0bfa9d843fb9e16b6b34f67193d863f2bd45617163a56b9528b1053f0fdef6173f2c46";

string r1_hex = "e963ffdfe34e63b68aeb42a5826e08af087660e0dac1c3e79f7625ca4e6ae482";
string s1_hex = "389c58392292e9cd6b777ddb093869a0b82839464c665f318b1d658cf840ad92";
string z1_hex = "289e5175e02c788c2d442cfe81d6be0533d8c13e253ef763fda45d37accfe4d4";

string r2_hex = "077be39ffaa0f27084ae102226ca6fc6e8ecc1b1ede683898b0bea201f09d30f";
string s2_hex = "29254b4c151d689930cdd3c0ffaec4881dc0977654ea5b8019d6dc7be06c0949";
string z2_hex = "a78521e49048b6e0d368d3fba417fc20c7546272dafa78a8a173fcca6c81233b";

string r3_hex = "c4b9ba86dc6537ada1562f7a1f8de117b6beee4394a488a384ddaa76613bf3af";
string s3_hex = "578a8a4b75de032701eaa9062a66e2a5fd4130493ff8d4b539748e26240041e2";
string z3_hex = "89da2bd31a5d008c84323c9693f12f09e62a75a688a55f2a6fd24660afba5660";

// d = ddd7d19c659ae145e1f15a6f6d3b0f5a8eed6b35353cfae93258a0e3d9cd77c1
// k1 = 0x12345, k2 = 0x12445, k3 = 0x12545
(venv) daro@mojkomputer:/mnt/c/Users/opini/Desktop/ALLKRYPTO/BreakingECDSAwithLLL$

============================================================
SPRAWDZENIE:
============================================================
Program obliczy początkowe k1 = 0x624f3bd2cbbea66202388ffa695fe374e389bf302c9aa8a785f55af01eef156d
Twoje k1 = 0x12345
⚠️ Program będzie musiał przeszukać 44466652965357683209636304439155918596911642408961063251733839822447602168360 wartości k1
   (to około 44466652965357681660706993772162769907544647152472412715774099096338432.00 milionów)

✅ Dane zapisano do pliku: test_signatures.txt
<img width="1544" height="673" alt="image" src="https://github.com/user-attachments/assets/0c515dda-44a6-48c6-ba94-0dddfea6956c" />



Custom difficulty cases

Made for educational purposes. Use responsibly. 🔐
