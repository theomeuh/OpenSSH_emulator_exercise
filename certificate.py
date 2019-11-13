import datetime
from typing import List

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import Certificate, Name
from cryptography.x509.oid import NameOID


class X509Certificate:
    def __init__(
        self,
        issuer: str,
        subject: str,
        public_key,
        private_key,
        validity_days: int,
        cert: Certificate = None,
    ):
        """
        Either create a brand new Certificate from given info or just load an already existing cert in this custom class
        """

        self._certificate: Certificate

        # TODO make better constructors
        if cert is None and (
            issuer and subject and public_key and private_key and validity_days
        ):
            # creates brand new certificate
            one_day = datetime.timedelta(1, 0, 0)
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
            )

            builder = builder.issuer_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
            )

            builder = builder.not_valid_before(datetime.datetime.today() - one_day)
            builder = builder.not_valid_after(
                datetime.datetime.today() + (one_day * validity_days)
            )

            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(public_key)

            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )

            self._certificate = builder.sign(
                private_key=private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend(),
            )
        elif cert is not None and not (
            issuer or subject or public_key or private_key or validity_days
        ):
            # loads an already existing cert
            self._certificate = cert

    # another constructor
    @classmethod
    def load_from_pem(cls, pem_data: bytes) -> "X509Certificate":
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        return cls(None, None, None, None, None, cert)

    def __repr__(self):
        s = "{}     Serial number: {}\n".format(
            self._certificate.version, self._certificate.serial_number
        )
        s += "Valid from {} to {}\n".format(
            self._certificate.not_valid_before, self._certificate.not_valid_after
        )
        s += "Issuer: {}    Subject: {}\n".format(self.issuer(), self.subject())
        s += "Public key: {}\n".format(self._certificate.public_key().public_numbers())
        s += "Signature: {}\n".format(self._certificate.signature.hex())
        return s

    def __hash__(self):
        return hash(self.cert_pem())

    def __eq__(self, other):
        return hash(self) == hash(other)

    def public_key(self) -> rsa.RSAPublicKey:
        return self._certificate.public_key()

    def subject(self) -> str:
        return self._certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
            0
        ].value

    def issuer(self) -> str:
        return self._certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[
            0
        ].value

    def cert_pem(self) -> bytes:
        """
        output a pem file sendable in a socket
        """
        pem = self._certificate.public_bytes(encoding=serialization.Encoding.PEM)
        return pem

    @staticmethod
    def verify(cert: "X509Certificate", public_key: rsa.RSAPublicKey) -> bool:
        """
        return weither the certificate is valid or not
        """
        try:
            public_key.verify(
                cert._certificate.signature,
                cert._certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert._certificate.signature_hash_algorithm,
            )
        except InvalidSignature as e:
            print("InvalidSignature")
            return False

        today = datetime.datetime.today()
        if (
            cert._certificate.not_valid_after < today
            or cert._certificate.not_valid_before > today
        ):
            print("Certificate out of date")
            return False
        return True

    @staticmethod
    def verify_chain(
        first_pubkey: rsa.RSAPublicKey,
        chain: List["X509Certificate"],
        last_pubkey: rsa.RSAPublicKey,
    ) -> bool:
        """
        tests with the sequence defined by the list, if the chain of certificate is valid for this very certificate.
        In particular, it checks if certificates are valid one by one and then if they chain well two by two in sequence
        
        A proves to B that they are related if B can verify such a chain with the function
        [CertB(PubC1), CertC1(PubC2), ..., CertCn(PubCn+1), CertCn+1(PubA)]

        :first_pubkey in B's pubkey
        """

        if list(chain) == []:
            raise ValueError("Empty list")

        if chain[-1].public_key().public_numbers() != last_pubkey.public_numbers():
            raise ValueError("The chain does not end with the right certificate")

        pubkey = first_pubkey
        for cert in chain:
            if not X509Certificate.verify(cert, pubkey):
                return False
            pubkey = cert.public_key()
        print("chain of cert is valid")
        return True


class NotValidCertificate(Exception):
    def __init__(self, value):
        self.message = value

    def __str__(self):
        return self.message
