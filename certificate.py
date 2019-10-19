from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime


class X509Certificate:
    def __init__(
        self, issuer: str, subject: str, public_key, private_key, validity_days: int
    ):
        self._certificate: Certificate

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

    def __repr__(self):
        s = "{}     Serial number: {}\n".format(
            self._certificate.version, self._certificate.serial_number
        )
        s += "Valid from {} to {}\n".format(
            self._certificate.not_valid_before, self._certificate.not_valid_after
        )
        s += "Issuer: {}    Subject: {}\n".format(
            self._certificate.issuer, self._certificate.subject
        )
        s += "Public key: {}\n".format(self._certificate.public_key().public_numbers())
        s += "Signature: {}\n".format(self._certificate.signature.hex())
        return s
