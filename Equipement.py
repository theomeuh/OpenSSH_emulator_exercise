from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


class Equipment:
    def __init__(self, name: str, port: int):
        self.name = name
        self.port = port
        self.key_pair = private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def __repr__(self):
        s = "My name is {} and my port is {}\n".format(self.name, self.port)
        s += "My public key is {}\n".format(self.key_pair.public_key().public_numbers())
        return s
