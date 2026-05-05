import random

#1. Miller Rabin Primality Test

def MRT(n,k=10):
    "The test returns true if n is probably prime"
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 ==0: return False

    #write n-1 as 2^r *d
    r, d = 0, n-1 
    while d % 2 == 0:
        r += 1
        d //=2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n -1:
            continue
    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            break
    else:
        return False
    return True
    
def generate_prime(bits=512):
    "Generate a radnom prime give bit length using MRT"
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1 #odd correct bit length
        if MRT(p):
            return p
        
#2. Euclidean Algorithm

def EA(a, b):
    """Return gcd(a, b) using the Euclidean Algorithm."""
    while b:
        a, b = b, a % b
    return a

#3. Extended Euclidean  Algorithm

def EEA(a, m):
    """Return x such that a*x ≡ 1 (mod m) using the Extended Euclidean Algorithm."""
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m
 
 
def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

#4 Square and multiply 

def powmod_sm(base, exp, mod):
    """Compute base^exp % mod using square-and-multiply."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:          # if current bit is 1, multiply
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result

#5 RSA Key Generation/Encryption/Decryption
#Key Gen

def rsa_keygen(bits=512):
    # a) Choose two distinct primes p and q
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
 
    # b) n = p*q,  φ(n) = (p-1)*(q-1)
    n = p * q
    phi = (p - 1) * (q - 1)
 
    # c) Choose e with gcd(e, φ(n)) = 1
    while True:
        e = random.randint(2, phi - 1)
        if EA(e, phi) == 1:
            break
 
    # d) d = e^-1 mod φ(n),  ensure d >= 0.3*n_bits
    d = EEA(e, phi)
    min_d_bits = int(0.3 * (2 * bits))   # n has ~2*bits bits
    while d.bit_length() < min_d_bits:
        # retry with a new e if d is too small
        while True:
            e = random.randint(2, phi - 1)
            if EA(e, phi) == 1:
                break
        d = EEA(e, phi)
 
    # e) Public key (n, e)  |  Private key (d)
    return (n, e), d

#Encryption

def rsa_encrypt(public_key, x):
    """Encrypt plaintext integer x with public key (n, e)."""
    n, e = public_key
    if not (0 <= x < n):
        raise ValueError("Plaintext must be in [0, n)")
    return powmod_sm(x, e, n)

#Decryption

def rsa_decrypt(private_key, n, y):
    """Decrypt ciphertext integer y with private key d."""
    return powmod_sm(y, private_key, n)


#DEMO

if __name__ == "__main__":
    BITS = 512
    print("=" * 60)
    print("        RSA Demo  (512-bit primes)")
    print("=" * 60)
 
    # Key generation
    print("\n[1] Generating keys …")
    pub, priv = rsa_keygen(BITS)
    n, e = pub
    print(f"    n  ({n.bit_length()} bits): {str(n)[:60]}…")
    print(f"    e  ({e.bit_length()} bits): {e}")
    print(f"    d  ({priv.bit_length()} bits): {str(priv)[:60]}…")
 
    # Random plaintext
    x = random.randint(1, n - 1)
    print(f"\n[2] Plaintext  x: {str(x)[:60]}…")
 
    # Encryption
    y = rsa_encrypt(pub, x)
    print(f"\n[3] Ciphertext y: {str(y)[:60]}…")
 
    # Decryption
    x_dec = rsa_decrypt(priv, n, y)
    print(f"\n[4] Decrypted  x: {str(x_dec)[:60]}…")
 
    # Verify
    print(f"\n[5] Match: {x == x_dec}")
    print("=" * 60)
