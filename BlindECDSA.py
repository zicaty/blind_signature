from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from fastecdsa.util import mod_inv
import hashlib
import os
from typing import Tuple, Optional

class BlindECDSA:
    def __init__(self):
        self.curve = secp256k1
        self.G = self.curve.G
        self.n = self.curve.q

    def generate_keypair(self) -> Tuple[int, Point]:
        """Generate private and public key pair"""
        private_key = int.from_bytes(os.urandom(32), 'big') % self.n
        public_key = private_key * self.G
        return private_key, public_key

    def hash_message(self, message: bytes) -> int:
        """Hash message to integer"""
        h = hashlib.sha256(message).digest()
        return int.from_bytes(h, 'big') % self.n

    def blind_message(self, message: bytes, signer_pubkey: Point) -> Tuple[int, int, int, Point]:
        """User: Blind the message"""
        # Generate blinding factors
        alpha = int.from_bytes(os.urandom(32), 'big') % self.n
        beta = int.from_bytes(os.urandom(32), 'big') % self.n
        
        # Calculate R' = alpha*G + beta*Q
        R_prime = (alpha * self.G) + (beta * signer_pubkey)
        
        # Calculate message hash
        m = self.hash_message(message)
        
        # Calculate blinded message
        m_prime = (alpha * m + beta * R_prime.x) % self.n
        
        return m_prime, alpha, beta, R_prime

    def sign_blinded(self, m_prime: int, private_key: int) -> int:
        """Signer: Sign the blinded message"""
        k = int.from_bytes(os.urandom(32), 'big') % self.n
        R = k * self.G
        r = R.x % self.n
        
        s_prime = (mod_inv(k, self.n) * (m_prime + r * private_key)) % self.n
        return s_prime

    def unblind_signature(self, s_prime: int, alpha: int, beta: int, R_prime: Point) -> Tuple[int, int]:
        """User: Unblind the signature"""
        r = R_prime.x % self.n
        s = (mod_inv(alpha, self.n) * (s_prime - beta)) % self.n
        return r, s

    def verify(self, message: bytes, signature: Tuple[int, int], public_key: Point) -> bool:
        """Verify the signature"""
        r, s = signature
        if not (0 < r < self.n and 0 < s < self.n):
            return False

        m = self.hash_message(message)
        s_inv = mod_inv(s, self.n)
        u1 = (m * s_inv) % self.n
        u2 = (r * s_inv) % self.n
        
        R = u1 * self.G + u2 * public_key
        return R.x % self.n == r