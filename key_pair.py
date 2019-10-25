from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyPair:
    def __init__(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def public_key(self) -> rsa.RSAPublicKey:
        return self._private_key.public_key()

    def private_key(self) -> rsa.RSAPrivateKey:
        return self._private_key

    @classmethod
    def pubkey_pem(cls, pubkey) -> bytes:
        return pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @classmethod
    def load_pub_from_pem(cls, data) -> rsa.RSAPublicKey:
        return serialization.load_pem_public_key(data=data, backend=default_backend())
