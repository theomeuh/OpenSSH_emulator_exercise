import pytest
from unittest import mock

from certificate import X509Certificate, NotValidCertificate
from key_pair import KeyPair


class TestCert2Cert:
    def test_cert_to_pem_to_cert(self):
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


class TestFailCertEqCert:
    def test_certEqcert_kp(self):
        kp1 = KeyPair()
        cert1 = X509Certificate(
            issuer="issuer",
            subject="subject",
            public_key=kp1.public_key(),
            private_key=kp1.private_key(),
            validity_days=10,
        )
        kp2 = KeyPair()
        cert2 = X509Certificate(
            issuer="issuer",
            subject="subject",
            public_key=kp2.public_key(),
            private_key=kp2.private_key(),
            validity_days=10,
        )
        with pytest.raises(AssertionError):
            assert cert1 == cert2

        assert cert1 != cert2

    def test_certEqcert_names(self):
        kp = KeyPair()
        cert1 = X509Certificate(
            issuer="issuer",
            subject="subject",
            public_key=kp.public_key(),
            private_key=kp.private_key(),
            validity_days=10,
        )
        cert2 = X509Certificate(
            issuer="other_issuer",
            subject="other_subject",
            public_key=kp.public_key(),
            private_key=kp.private_key(),
            validity_days=10,
        )
        with pytest.raises(AssertionError):
            assert cert1 == cert2

        assert cert1 != cert2


class TestVerify:
    def test_selfsigned_cert(self):
        kp = KeyPair()
        cert = X509Certificate(
            issuer="issuer",
            subject="subject",
            public_key=kp.public_key(),
            private_key=kp.private_key(),
            validity_days=10,
        )
        X509Certificate.verify(cert, kp.public_key())

    def test_good_cert(self):
        pubkey_to_signed = KeyPair().public_key()

        kp_root = KeyPair()

        cert = X509Certificate(
            issuer="issuer",
            subject="subject",
            public_key=pubkey_to_signed,
            private_key=kp_root.private_key(),
            validity_days=10,
        )
        X509Certificate.verify(cert, kp_root.public_key())

    def test_wrong_pubkey(self):
        pubkey_to_signed = KeyPair().public_key()

        kp_root = KeyPair()

        cert = X509Certificate(
            issuer="issuer",
            subject="subject",
            public_key=pubkey_to_signed,
            private_key=kp_root.private_key(),
            validity_days=10,
        )
        assert not X509Certificate.verify(cert, pubkey_to_signed)

    # TODO: change the validity date and check good output


class TestVerifyChain:
    """
    Test if the chaining is well done
    """

    def test_chain_0_element(self):
        """
        Should raise an error cause there is no chain
        """
        chain = []
        kp = KeyPair()
        cert = X509Certificate(
            issuer="issuer",
            subject="subject",
            public_key=kp.public_key(),
            private_key=kp.private_key(),
            validity_days=10,
        )
        with pytest.raises(ValueError):
            X509Certificate.verify_chain(kp.public_key(), chain)

    def test_chain_1_element(self):
        """"
        An equipment automaticaly verify a chain with only it inside
        """
        chain = []
        kp = KeyPair()
        cert = X509Certificate(
            issuer="issuer",
            subject="subject",
            public_key=kp.public_key(),
            private_key=kp.private_key(),
            validity_days=10,
        )
        chain.append(cert)
        X509Certificate.verify_chain(kp.public_key(), chain)

    @pytest.mark.parametrize("cert_count", [2, 5, 10])
    def test_chain_X_elements(self, cert_count):
        """
        Chain with X valid certificates
        """
        chain = []
        kp_root = KeyPair()

        privkey = kp_root.private_key()
        for i in range(cert_count):
            kp_next = KeyPair()
            pubkey = kp_next.public_key()
            cert = X509Certificate(
                issuer="issuer",
                subject="subject",
                public_key=kp_next.public_key(),
                private_key=privkey,
                validity_days=10,
            )
            privkey = kp_next.private_key()
            chain.append(cert)

        X509Certificate.verify_chain(kp_root.public_key(), chain)
