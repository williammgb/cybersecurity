from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

class Encryption:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) # larger key_size means higher security
        self.public_key = self.private_key.public_key() # public key is for encryption, private for decryption
        
    @staticmethod
    def encrypt_rsa(public_key, data: bytes) -> bytes:
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ) # padding adds randomness and protection to encryption

    def decrypt_rsa(self, encrypted_data: bytes) -> bytes:
        return self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def encrypt_message(node_encryption, content: str) -> dict:
        """Session key (one time) is encrypted and added to message."""
        fernet_key = Fernet.generate_key()
        f = Fernet(fernet_key)
        public_key = node_encryption.public_key
        enc_key = Encryption.encrypt_rsa(public_key, fernet_key)
        enc_content = f.encrypt(content.encode())
        return {
            'encrypted_key': enc_key,
            'content': enc_content
        }

    def decrypt_message(self, packet: dict) -> str:
        fernet_key = self.decrypt_rsa(packet["encrypted_key"])
        f = Fernet(fernet_key)
        content = f.decrypt(packet['content'])
        return content.decode()


