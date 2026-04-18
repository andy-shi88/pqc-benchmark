import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


class RegularCrypto:
    """Regular Cryptography class using ECDH-X25519 for key exchange"""
    
    def __init__(self, algorithm="ECDH-X25519"):
        """Initialize RegularCrypto with X25519 algorithm"""
        self.algorithm = algorithm
        self.public_key = None
        self.secret_key = None
        self.private_key_obj = None

    
    def generate_key(self):
        """Generate X25519 key pair with time tracking"""
        start_time = time.time()
        self.private_key_obj = X25519PrivateKey.generate()
        public_key_obj = self.private_key_obj.public_key()
        
        # Export keys as bytes (similar to OQS format)
        self.public_key = public_key_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.secret_key = self.private_key_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        end_time = time.time()
        return end_time - start_time
    
    def sign_data(self):
        """Perform ECDH (generate ephemeral key and shared secret) with time tracking"""
        start_time = time.time()
        
        # Check if public key is generated
        if self.public_key is None:
            raise Exception("Public key not generated. Please generate a key pair first.")
        
        # Generate ephemeral key pair for the sender
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        # Compute shared secret using ephemeral private and receiver's public
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        receiver_public_key = X25519PublicKey.from_public_bytes(self.public_key)
        shared_secret = ephemeral_private.exchange(receiver_public_key)
        
        # Return ephemeral public key as "ciphertext"
        ciphertext = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        end_time = time.time()
        
        return end_time - start_time, ciphertext
    
    def verify_signature(self, signature=None):
        """Perform ECDH (recover shared secret from ephemeral public key) with time tracking"""
        start_time = time.time()
        
        # Check if secret key and signature (ephemeral public key) are provided
        if self.secret_key is None or self.private_key_obj is None:
            raise Exception("Secret key not generated. Please generate a key pair first.")
        
        if signature is None:
            raise Exception("Ephemeral public key not provided. Please perform key exchange first.")
        
        # Reconstruct ephemeral public key from signature
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        ephemeral_public_key = X25519PublicKey.from_public_bytes(signature)
        
        # Compute shared secret using our private key and ephemeral public key
        shared_secret = self.private_key_obj.exchange(ephemeral_public_key)
        
        end_time = time.time()
        
        return end_time - start_time
