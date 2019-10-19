from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyPair:
    def __init__(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def public_key(self):
        return self._private_key.public_key()

    def private_key(self):
        return self._private_key
