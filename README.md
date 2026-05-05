# Project-3-RSA
RSA encryption implementation in Python using Miller-Rabin primality testing, Euclidean algorithms, and square-and-multiply exponentiation.


# RSA Implementation – CSCI 360

RSA public-key cryptography in Python.

## Features
- Miller-Rabin Primality Test to generate 512-bit primes
- Euclidean Algorithm for gcd verification
- Extended Euclidean Algorithm for modular inverse
- Square-and-Multiply for efficient modular exponentiation
- Full RSA key generation, encryption, and decryption

## Usage
RSA3.py

## How it works
Key generation produces a 1024-bit public/private key pair. A random plaintext
is encrypted with the public key and decrypted with the private key, with a
match check confirming correctness.
