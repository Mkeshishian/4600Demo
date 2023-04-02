import random

# Compute modular exponentiation (base^exponent) % modulus
def mod_exp(base, exponent, modulus):
    return pow(base, exponent, modulus)

# Extended Euclidean Algorithm to find GCD and coefficients x, y
def xgcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

# Compute modular multiplicative inverse of a under modulus m
def mod_inv(a, m):
    g, x, _ = xgcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m

# Generate ElGamal key pair
def elgamal_key_generation(prime, generator):
    private_key = random.randint(2, prime - 1)  # Generate private key (random int)
    public_key = mod_exp(generator, private_key, prime)  # Compute public key using mod_exp
    return private_key, public_key  # Return private and public keys

# ElGamal encryption
def elgamal_encrypt(plain_text, prime, generator, public_key):
    k = random.randint(1, prime - 1)  # Generate random integer k
    s = mod_exp(public_key, k, prime)  # Compute shared secret s = h^k
    c1 = mod_exp(generator, k, prime)  # Compute c1 = g^k
    c2 = (plain_text * s) % prime  # Compute c2 = M * s
    return c1, c2   # Return c1 and c2 values

# ElGamal decryption
def elgamal_decrypt(c1, c2, prime, private_key):
    s = mod_exp(c1, private_key, prime)  # Compute shared secret s = c1^a = (g^k)^a = h^k
    s_inv = mod_inv(s, prime)  # Compute s^-1 (modular multiplicative inverse)
    plain_text = (c2 * s_inv) % prime  # Compute decrypted message M = c2 * s^-1
    return plain_text   # Return plaint text

# Convert a string to an integer using UTF-8 encoding
def string_to_int(s):
    return int.from_bytes(s.encode('utf-8'), 'big')

# Convert an integer to a string using UTF-8 encoding
def int_to_string(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')

# Main
if __name__ == "__main__":
    prime = 0xFFFFFFFBFFFFFFFFFFFFFFFFFFFFFFA7  # 128-bit prime number
    generator = 5  # Define generator

    # Generate ElGamal key pair
    private_key, public_key = elgamal_key_generation(prime, generator)
    print(f"Private key: {private_key}\nPublic key: {public_key}")

    # Input plain text string and convert it to an integer
    plain_text_str = input("Enter the plain text message (string): ")
    plain_text_int = string_to_int(plain_text_str)
    print(f"Plain text (integer representation): {plain_text_int}")

    # Encryption
    c1, c2 = elgamal_encrypt(plain_text_int, prime, generator, public_key)
    print(f"Encrypted text: (c1: {c1}, c2: {c2})")

    # Decryption
    decrypted_text_int = elgamal_decrypt(c1, c2, prime, private_key)
    decrypted_text_str = int_to_string(decrypted_text_int)
    print(f"Decrypted text: {decrypted_text_str}")