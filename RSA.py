import gmpy2
from gmpy2 import mpz, gcd, invert, is_prime, random_state, mpz_rrandomb
import os
import base64
import hashlib
class RSA:
    def __init__(self, bits=2048):
        self.bits = bits
        seed = int.from_bytes(os.urandom(16), byteorder='big')
        self.random_state = random_state(seed)
        self.p = None
        self.q = None
        self.n = None
        self.phi_n = None
        self.e = None
        self.d = None
        self.dP = None
        self.dQ = None
        self.qInv = None
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        self.p = self.generate_large_prime()
        self.q = self.generate_large_prime()
        while self.p == self.q:
            self.q = self.generate_large_prime()
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.e = mpz(65537)
        if gcd(self.e, self.phi_n) != 1:
            raise ValueError("e and phi(n) are not coprime")
        self.d = invert(self.e, self.phi_n)
        self.dP = self.d % (self.p - 1)
        self.dQ = self.d % (self.q - 1)
        self.qInv = invert(self.q, self.p)
        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)

    def generate_large_prime(self):
        while True:
            candidate = mpz_rrandomb(self.random_state, self.bits)
            if is_prime(candidate, 25):
                return candidate

    def encrypt(self, message):
        e, n = self.public_key
        cipher = pow(mpz(message), e, n)
        return cipher

    def decrypt(self, cipher):
        m1 = pow(cipher, self.dP, self.p)
        m2 = pow(cipher, self.dQ, self.q)
        h = (self.qInv * (m1 - m2)) % self.p
        message = m2 + h * self.q
        return message

    def sign(self, message):
        message_hash = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
        signature = pow(mpz(message_hash), self.d, self.n)
        return signature

    def verify(self, message, signature):
        message_hash = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
        signature_hash = pow(mpz(signature), self.e, self.n)
        return message_hash == signature_hash

    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.private_key

    def export_key_pem(self, key, key_type='public'):
        if key_type == 'public':
            e, n = key
            key_components = f"Modulus: {n}\nExponent: {e}\n"
            pem_header = "-----BEGIN RSA PUBLIC KEY-----"
            pem_footer = "-----END RSA PUBLIC KEY-----"
        elif key_type == 'private':
            d, n = key
            key_components = (
                f"Modulus: {n}\n"
                f"PublicExponent: {self.e}\n"
                f"PrivateExponent: {d}\n"
                f"Prime1: {self.p}\n"
                f"Prime2: {self.q}\n"
                f"Exponent1: {self.dP}\n"
                f"Exponent2: {self.dQ}\n"
                f"Coefficient: {self.qInv}\n"
            )
            pem_header = "-----BEGIN RSA PRIVATE KEY-----"
            pem_footer = "-----END RSA PRIVATE KEY-----"
        else:
            raise ValueError("Invalid key type specified")

        key_bytes = key_components.encode('utf-8')
        key_b64 = base64.encodebytes(key_bytes).decode('utf-8')
        pem_key = f"{pem_header}\n{key_b64}{pem_footer}"
        return pem_key

    def import_key_pem(self, pem_key, key_type='public'):
        key_b64 = pem_key.strip().split('\n')[1:-1]
        key_bytes = base64.decodebytes('\n'.join(key_b64).encode('utf-8'))
        key_components = dict(line.split(': ') for line in key_bytes.decode('utf-8').split('\n') if line)

        if key_type == 'public':
            self.n = mpz(key_components['Modulus'])
            self.e = mpz(key_components['Exponent'])
            self.public_key = (self.e, self.n)
        elif key_type == 'private':
            self.n = mpz(key_components['Modulus'])
            self.e = mpz(key_components['PublicExponent'])
            self.d = mpz(key_components['PrivateExponent'])
            self.p = mpz(key_components['Prime1'])
            self.q = mpz(key_components['Prime2'])
            self.dP = mpz(key_components['Exponent1'])
            self.dQ = mpz(key_components['Exponent2'])
            self.qInv = mpz(key_components['Coefficient'])
            self.private_key = (self.d, self.n)
            self.public_key = (self.e, self.n)
        else:
            raise ValueError("Invalid key type specified")