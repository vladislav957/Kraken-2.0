from cryptography.hazmat.primitives.asymmetric import rsa, padding
#from cryptography.hazmat.primitives.asymmetric import hasher, serilization
import hashlib
import time

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, data: bytes)->bytes:
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashlib.sha256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashlib.sha256()
        )
    return signature

def varify_signature(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_keyu.verfy(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashlib.sha256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashlib.sha256()

            )
        return True
    except:
        return False
    
