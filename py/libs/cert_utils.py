from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime
import os

def generate_csr(common_name: str, key_path: str, csr_path: str):
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    print(f"[CertUtils] Generating private key at: {key_path}")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Write private key to file
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"[CertUtils] Private key saved to: {key_path}")
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])).sign(key, hashes.SHA256())

  
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"[CertUtils] CSR saved to: {csr_path}")