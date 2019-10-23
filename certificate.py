import datetime

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
        self._private_key = private_key

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

    @staticmethod
    def verify(cert: "X509Certificate", public_key):
        """
        raises error if the certificate is not valid, else does nothing 
        """
        try:
            public_key.verify(
                cert._certificate.signature,
                cert._certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert._certificate.signature_hash_algorithm,
            )
        except InvalidSignature as e:
            raise NotValidCertificate("InvalidSignature")

        today = datetime.datetime.today()
        if (
            cert._certificate.not_valid_after < today
            or cert._certificate.not_valid_before > today
        ):
            raise NotValidCertificate("Certificate out of date")

    def cert_pem(self) -> bytes:
        """
        output a pem file sendable in a socket
        """
        pem = self._certificate.public_bytes(encoding=serialization.Encoding.PEM)
        return pem

    def public_key(self):
        return self._certificate.public_key()

    def subject(self) -> Name:
        return self._certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
            0
        ].value

    def issuer(self) -> Name:
        return self._certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[
            0
        ].value


class NotValidCertificate(Exception):
    def __init__(self, value):
        self.message = message

    def __str__(self):
        return self.message
