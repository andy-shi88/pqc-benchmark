import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class RegularSignature:
    """Regular Signature class supporting RSA-2048 and ECDSA-P256"""
    
    def __init__(self, algorithm="RSA-2048"):
        """Initialize RegularSignature with the specified algorithm"""
        self.algorithm = algorithm
        self.public_key = None
        self.secret_key = None
        self.private_key_obj = None
        self.public_key_obj = None
        self.message = b"0" * 32  # 32 bytes message to sign

    
    def generate_key(self):
        """Generate key pair with time tracking"""
        start_time = time.time()
        
        if self.algorithm == "RSA-2048":
            self.private_key_obj = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key_obj = self.private_key_obj.public_key()
            
            # Export keys as bytes
            self.public_key = self.public_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.secret_key = self.private_key_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
        elif self.algorithm == "ECDSA-P256":
            self.private_key_obj = ec.generate_private_key(
                ec.SECP256R1(),
                backend=default_backend()
            )
            self.public_key_obj = self.private_key_obj.public_key()
            
            # Export keys as bytes
            self.public_key = self.public_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.secret_key = self.private_key_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        end_time = time.time()
        return end_time - start_time
    
    def sign_data(self):
        """Sign the message with time tracking"""
        start_time = time.time()
        
        # Check if private key is generated
        if self.private_key_obj is None:
            raise Exception("Private key not generated. Please generate a key pair first.")
        
        # Sign the message
        if self.algorithm == "RSA-2048":
            signature = self.private_key_obj.sign(
                self.message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif self.algorithm == "ECDSA-P256":
            signature = self.private_key_obj.sign(
                self.message,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        end_time = time.time()
        
        return end_time - start_time, signature
    
    def verify_signature(self, signature=None):
        """Verify the signature with time tracking"""
        start_time = time.time()
        
        # Check if public key and signature are provided
        if self.public_key_obj is None:
            raise Exception("Public key not generated. Please generate a key pair first.")
        
        if signature is None:
            raise Exception("Signature not provided. Please sign first.")
        
        # Verify the signature
        try:
            if self.algorithm == "RSA-2048":
                self.public_key_obj.verify(
                    signature,
                    self.message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            elif self.algorithm == "ECDSA-P256":
                self.public_key_obj.verify(
                    signature,
                    self.message,
                    ec.ECDSA(hashes.SHA256())
                )
            else:
                raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        except Exception as e:
            raise Exception(f"Signature verification failed: {e}")
        
        end_time = time.time()
        
        return end_time - start_time
