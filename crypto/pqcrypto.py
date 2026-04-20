import time
import oqs


class PQCrypto:
    """Post-Quantum Cryptography class for key generation, encapsulation, and decapsulation"""
    
    def __init__(self, algorithm="ML-KEM-512"):
        """Initialize PQCrypto with the specified KEM algorithm"""
        self.algorithm = algorithm
        self.kem = oqs.KeyEncapsulation(algorithm)
        self.public_key = None
        self.secret_key = None

    
    def generate_key(self):
        """Generate key pair with time tracking"""
        start_time = time.time()
        if self.algorithm in ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']:
            seed = b"This is a 64-byte seed for key generation" + b"\x00" * 23
            self.public_key = self.kem.generate_keypair_seed(seed)
        else:
            self.public_key = self.kem.generate_keypair()
        self.secret_key = self.kem.export_secret_key()
        end_time = time.time()
        return end_time - start_time
    
    def sign_data(self):
        """Encapsulate (generate shared secret and ciphertext) with time tracking"""
        start_time = time.time()
        
        # Check if public key is generated
        if self.public_key is None:
            raise Exception("Public key not generated. Please generate a key pair first.")
        
        # Encapsulate to generate ciphertext and shared secret
        ciphertext, shared_secret = self.kem.encap_secret(self.public_key)
        
        end_time = time.time()
        
        return end_time - start_time, ciphertext
    
    def verify_signature(self, signature=None):
        """Decapsulate (recover shared secret from ciphertext) with time tracking"""
        start_time = time.time()
        
        # Check if secret key and ciphertext are provided
        if self.secret_key is None:
            raise Exception("Secret key not generated. Please generate a key pair first.")
        
        if signature is None:
            raise Exception("Ciphertext not provided. Please encapsulate first.")
        
        # Decapsulate to recover shared secret
        shared_secret = self.kem.decap_secret(signature)
        
        end_time = time.time()
        
        return end_time - start_time
