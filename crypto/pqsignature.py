import time
import oqs


class PQSignature:
    """Post-Quantum Signature class for signing and verification"""
    
    def __init__(self, algorithm="ML-DSA-44"):
        """Initialize PQSignature with the specified signature algorithm"""
        self.algorithm = algorithm
        self.sig = oqs.Signature(algorithm)
        self.public_key = None
        self.secret_key = None
        self.message = b"0" * 32  # 32 bytes message to sign

    
    def generate_key(self):
        """Generate key pair with time tracking"""
        start_time = time.time()
        self.public_key = self.sig.generate_keypair()
        self.secret_key = self.sig.export_secret_key()
        end_time = time.time()
        return end_time - start_time
    
    def sign_data(self):
        """Sign the message with time tracking"""
        start_time = time.time()
        
        # Check if secret key is generated
        if self.secret_key is None:
            raise Exception("Secret key not generated. Please generate a key pair first.")
        
        # Sign the message
        signature = self.sig.sign(self.message)
        
        end_time = time.time()
        
        return end_time - start_time, signature
    
    def verify_signature(self, signature=None):
        """Verify the signature with time tracking"""
        start_time = time.time()
        
        # Check if public key and signature are provided
        if self.public_key is None:
            raise Exception("Public key not generated. Please generate a key pair first.")
        
        if signature is None:
            raise Exception("Signature not provided. Please sign first.")
        
        # Verify the signature
        is_valid = self.sig.verify(self.message, signature, self.public_key)
        
        if not is_valid:
            raise Exception("Signature verification failed")
        
        end_time = time.time()
        
        return end_time - start_time
