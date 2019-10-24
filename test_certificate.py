import pytest

from certificate import X509Certificate
from key_pair import KeyPair


def test_cert_to_pem_to_cert():
    kp = KeyPair()
    cert1 = X509Certificate(
        issuer="issuer",
        subject="subject",
        public_key=kp.public_key(),
        private_key=kp.private_key(),
        validity_days=10,
    )

    cert2 = X509Certificate.load_from_pem(cert1.cert_pem())
    
    assert cert1 == cert2
