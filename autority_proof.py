from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from certificate import X509Certificate
from key_pair import KeyPair


class AutorityProof:
    def __init__(self, issuer_key: RSAPublicKey, cert_from_issuer: X509Certificate):
        self.issuer_key = issuer_key
        self.cert_from_issuer = cert_from_issuer

    def __repr__(self):
        return "my hash (id): {}".format(hash(self))

    def __hash__(self):
        return hash(self.cert_from_issuer)

    def __eq__(self, other):
        if not isinstance(other, AutorityProof):
            raise TypeError
        return hash(self) == hash(other)

    def pem(self) -> Tuple[bytes, bytes]:
        return (KeyPair.pubkey_pem(self.issuer_key), self.cert_from_issuer.cert_pem())

    @classmethod
    def load(cls, tupl: Tuple[bytes, bytes]) -> "AutorityProof":
        return cls(
            KeyPair.load_pub_from_pem(tupl[0]), X509Certificate.load_from_pem(tupl[1])
        )
