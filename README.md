DONATE: bc1qps62cyk9f9unmdkc9k3ccj9e2h8ywfhg2j53ec

Built with ❤️ for the crypto research community.
# ECDSA Private Key Finder for secp256k1

## 1. Main Goal
The program searches for a private key (d) that corresponds to a given public key (pubkey) on the secp256k1 elliptic curve (used in Bitcoin).

## 2. Input Data
The program uses:
- **Public key (pubkey)** - 65-byte hex string
- **Two ECDSA signatures** - each containing:
  - **r** - signature value
  - **s** - signature value
  - **z** - message hash

## 3. Mechanism of Action

### Step-by-step:

#### A. Generate random nonce (k1)
- The program randomly selects a value k1 (first nonce) from the range [1, n-1]
- This is done in a loop, trying different values

#### B. Calculate private key (d)
- Uses the ECDSA equation: `s1 = k1^(-1) * (z1 + r1*d) mod n`
- Transforms it to calculate: `d = (s1*k1 - z1) / r1 mod n`

#### C. Calculate second nonce (k2)
- Having d, calculates k2 from the second signature:
- `k2 = (z2 + r2*d) / s2 mod n`

#### D. Verify correctness
- Checks if the calculated values satisfy the ECDSA equations
- Compares the calculated s2_check with the original s2

#### E. Check public key
- Calculates the public key from the found d
- Compares it with the expected public key

## 4. Additional Checks
The program verifies two mathematical relationships:

**Equation 1:** `s1*k1 - s2*k2 = z1 - z2 + d*(r1 - r2)`
- Derived from subtracting the ECDSA equations for both signatures

**Equation 2:** `(s1*k1 - z1)/r1 = (s2*k2 - z2)/r2`
- Derived from eliminating d from both equations

## 5. Progress Monitoring
The program displays:
- Number of attempts
- Number of mathematical solutions found (solutions_found)
- Elapsed time
- Generation speed (k1/s)
- Every 1000 solutions, it displays details

## 6. Completion
When it finds a private key that:
- Satisfies all equations
- Generates the correct public key

The program displays:
- Found private key (d)
- Both nonces (k1, k2)
- Time and statistics

## Why does this work?
The program exploits the fact that if two signatures were created using the same private key (but different nonces), then you can:

1. Generate a random k1
2. Calculate d from the first equation
3. Calculate k2 from the second equation
4. Check if everything matches

Since the k1 space is enormous (2^256), in practice finding the correct solution can take a very long time - the program uses random searching.

## Summary
This is a cryptographic bruteforcer that:
- Attempts to break an ECDSA private key
- Uses two signatures created with the same key
- Applies advanced elliptic curve mathematics
- Displays detailed statistics and verifications
- Is written in C++ using the OpenSSL library
