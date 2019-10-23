import socket

from certificate import X509Certificate
from key_pair import KeyPair


class Equipment:
    def __init__(self, name: str, port: int):
        self.name = name
        self.port = port
        self.CA = set()  # Certification autorities
        self.DA = set()  # Derived autorities
        self.key_pair = KeyPair()
        self.certificate = X509Certificate(
            self.name,
            self.name,
            self.key_pair.public_key(),
            self.key_pair.private_key(),
            10,
        )
        X509Certificate.verify(self.certificate, self.key_pair.public_key())
        print(self)

    def __repr__(self):
        s = "My name is {} and my port is {}\n".format(self.name, self.port)
        s += "My public key is {}\n".format(self.key_pair.public_key().public_numbers())
        s += "My certificate is:\n{}\n".format(self.certificate)
        return s

    def server(self):
        print("I play server and wait on port {}".format(self.port))
        with socket.socket() as s:
            s.bind(("localhost", self.port))
            s.listen()
            conn, addr = s.accept()  # conn is a socket connected to addr
            with conn:
                print("Connected by", addr)
                while True:
                    resp = input("Connect a new device ? (y/n)")
                    if resp == "y":
                        self.add_CA(conn)
                        break
                    elif resp == "n":
                        print("Nothing happened")
                        break
                    else:
                        print("Invalid answer")
            print("Closing connection")

    def client(self, addr: str, port: int):
        print("I play client and want to acces {} on port {}".format(addr, port))
        with socket.socket() as conn:
            conn.connect((addr, port))

            while True:
                resp = input("Connect a new device ? (y/n)")
                if resp == "y":
                    self.add_CA(conn)
                    break
                elif resp == "n":
                    print("Nothing happened")
                    break
                else:
                    print("Invalid answer")
        print("Closing connection")

    def show_certs(self):
        print("#" * 8 + "CA" + "#" * 8 + "\n{}".format(self.CA))
        print("#" * 8 + "DA" + "#" * 8 + "\n{}".format(self.DA))

    def add_CA(self, conn: socket.socket):
        """
        Equipments don't know each other and they need to exchange their
        certificate. The auth by DA set failed.
        """
        # send selfsigned certificate
        conn.sendall(self.certificate.cert_pem())

        # received the other's selfsigned certificate
        cert_selfsigned_received = X509Certificate.load_from_pem(conn.recv(1024))
        other_cert_pubkey = cert_selfsigned_received.public_key()
        X509Certificate.verify(cert_selfsigned_received, other_cert_pubkey)

        # send our certificate on its public key
        cert_to_sent = X509Certificate(
            issuer=self.name,
            subject=cert_selfsigned_received.issuer(),
            public_key=other_cert_pubkey,
            private_key=self.key_pair.private_key(),
            validity_days=10,
        )
        conn.sendall(cert_to_sent.cert_pem())

        # received its certificate on our public key
        cert_received = X509Certificate.load_from_pem(conn.recv(1024))
        X509Certificate.verify(cert_received, other_cert_pubkey)

        self.CA.add(cert_received)
