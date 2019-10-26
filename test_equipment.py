import pytest

from equipment import Equipment
from key_pair import KeyPair
from certificate import X509Certificate
from autority_proof import AutorityProof


class TestChainCertif:
    def test_gen_good_chain_line(self):
        """
        tests weither equipment A can create a chain to B via C

        B -> C -> A
        """
        equipmentA = Equipment(name="name", port=8888)

        chain = set()
        kp_B = KeyPair()
        kp_C = KeyPair()
        kp_A = equipmentA.key_pair

        cert_BC = X509Certificate(
            issuer="B",
            subject="C",
            public_key=kp_C.public_key(),
            private_key=kp_B.private_key(),
            validity_days=10,
        )

        cert_CA = X509Certificate(
            issuer="C",
            subject="A",
            public_key=kp_A.public_key(),
            private_key=kp_C.private_key(),
            validity_days=10,
        )

        equipmentA.DA.add(
            AutorityProof(issuer_key=kp_B.public_key(), cert_from_issuer=cert_BC)
        )
        equipmentA.DA.add(
            AutorityProof(issuer_key=kp_C.public_key(), cert_from_issuer=cert_CA)
        )

        assert equipmentA.create_cert_chain(kp_B.public_key()) == [cert_BC, cert_CA]

    def test_gen_good_chain_dual(self):
        r"""
        tests weither equipment A can create a chain to B and then to D

        B -> C -> A
          \      /
           D -> E 
        """
        equipmentA = Equipment(name="name", port=8888)

        chain = set()
        kp_B = KeyPair()
        kp_C = KeyPair()
        kp_A = equipmentA.key_pair
        kp_D = KeyPair()
        kp_E = KeyPair()

        cert_BC = X509Certificate(
            issuer="B",
            subject="C",
            public_key=kp_C.public_key(),
            private_key=kp_B.private_key(),
            validity_days=10,
        )
        equipmentA.DA.add(AutorityProof(kp_B.public_key(), cert_BC))

        cert_BD = X509Certificate(
            issuer="B",
            subject="D",
            public_key=kp_D.public_key(),
            private_key=kp_B.private_key(),
            validity_days=10,
        )
        equipmentA.DA.add(AutorityProof(kp_B.public_key(), cert_BD))

        cert_DE = X509Certificate(
            issuer="D",
            subject="E",
            public_key=kp_E.public_key(),
            private_key=kp_D.private_key(),
            validity_days=10,
        )
        equipmentA.DA.add(AutorityProof(kp_D.public_key(), cert_DE))

        cert_EA = X509Certificate(
            issuer="E",
            subject="A",
            public_key=kp_A.public_key(),
            private_key=kp_E.private_key(),
            validity_days=10,
        )
        equipmentA.DA.add(AutorityProof(kp_E.public_key(), cert_EA))

        cert_CA = X509Certificate(
            issuer="C",
            subject="A",
            public_key=kp_A.public_key(),
            private_key=kp_C.private_key(),
            validity_days=10,
        )
        equipmentA.DA.add(AutorityProof(kp_C.public_key(), cert_CA))

        assert equipmentA.create_cert_chain(kp_B.public_key()) == [cert_BC, cert_CA]
        assert equipmentA.create_cert_chain(kp_D.public_key()) == [cert_DE, cert_EA]
