import socket

from certificate import X509Certificate
from key_pair import KeyPair


class Equipment:
    def __init__(self, name: str, port: int):
        self.name = name
        self.port = port
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
                    data = conn.recv(1024)
                    if not data:
                        break
                    print("I received: {}".format(data))
                    conn.sendall(data)

    def client(self, addr: str, port: int):
        print("I play client and want to acces {} on port {}".format(addr, port))
        with socket.socket() as s:
            s.connect((addr, port))
            s.sendall(b"Hello, world")
            data = s.recv(1024)

    def show_certs(self):
        print("TO-DO afficher les certs")
