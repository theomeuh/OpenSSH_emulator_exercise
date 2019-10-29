import json
import socket
from collections import namedtuple
from typing import List, Set

from autority_proof import AutorityProof
from certificate import NotValidCertificate, X509Certificate
from dijsktra import Graph
from key_pair import KeyPair
from socket_tg import (  # use these functions instead of socket lib ones
    recv_all, recv_json, sendall)


class Equipment:
    def __init__(self, name: str, port: int):
        self.name = name
        self.port = port
        self.CA: Set[AutorityProof] = set()  # Certification autorities
        self.DA: Set[AutorityProof] = set()  # Derived autorities
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
            s.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
            )  # from python doc do reuse socket in TIME-WAIT state
            s.bind(("localhost", self.port))
            s.listen()
            conn, addr = s.accept()  # conn is a socket connected to addr
            with conn:
                print("Connected by", addr)
                self.a_la_pgp_process(conn=conn)

        print("Closing connection")

    def client(self, addr: str, port: int):
        print("I play client and want to acces {} on port {}".format(addr, port))
        with socket.socket() as conn:
            conn.connect((addr, port))
            print("Connected to", (addr, port))
            self.a_la_pgp_process(conn=conn)

        print("Closing connection")

    def show_certs(self):
        CA_certs = {
            AutorityProof(
                autority.issuer_key.public_numbers(), autority.cert_from_issuer
            )
            for autority in self.CA
        }
        DA_certs = {
            AutorityProof(
                autority.issuer_key.public_numbers(), autority.cert_from_issuer
            )
            for autority in self.DA
        }
        print("#" * 8 + " CA " + "#" * 8 + "\n{}".format(CA_certs))
        print("#" * 8 + " DA " + "#" * 8 + "\n{}".format(DA_certs))

    def update_CA(self, s: socket.socket, subject, pubkey):
        """
        Equipments don't know each other and they need to exchange their
        certificate. The auth by DA failed.

        :pubkey is the pubkey of the other equipment
        """
        # send our certificate on its public key
        cert_to_sent = X509Certificate(
            issuer=self.name,
            subject=subject,
            public_key=pubkey,
            private_key=self.key_pair.private_key(),
            validity_days=10,
        )
        sendall(s, cert_to_sent.cert_pem())

        # received its certificate on our public key
        cert_received = X509Certificate.load_from_pem(recv_all(s))
        X509Certificate.verify(cert_received, pubkey)

        self.CA.add(AutorityProof(pubkey, cert_received))
        print("CA update finished")

    def update_DA(self, s: socket.socket):
        """
        Send in the socket s, all certificates in personal CA and DA
        """
        self.DA.update(self.CA)

        for autorities in (self.CA, self.DA):
            # json is better with string, not bytes -> encode() / decode()
            _set = {}
            for autority in autorities:
                k = KeyPair.pubkey_pem(autority.issuer_key).decode()
                v = autority.cert_from_issuer.cert_pem().decode()
                _set[k] = v

            sendall(s, json.dumps(_set).encode())

            _received_json = recv_json(s)
            for (key, value) in _received_json.items():
                self.DA.add(
                    AutorityProof(
                        issuer_key=KeyPair.load_pub_from_pem(key.encode()),
                        cert_from_issuer=X509Certificate.load_from_pem(value.encode()),
                    )
                )
        print("DA update finished")

    def hand_shake(self, s: socket.socket) -> X509Certificate:
        """
        Exchanges selfsigned certificate with another equipment and verifies it
        """
        self.clean_sets()

        # send selfsigned certificate
        sendall(s, self.certificate.cert_pem())

        # received the other's selfsigned certificate
        cert_selfsigned_received = X509Certificate.load_from_pem(recv_all(s))
        other_cert_pubkey = cert_selfsigned_received.public_key()

        X509Certificate.verify(cert_selfsigned_received, other_cert_pubkey)
        return cert_selfsigned_received

    def is_in_CA(self, issuer_key) -> bool:
        """ 
        check if the a issuer_key is a known issuer_key of an AutorityProof is CA 
        and if the associated cert is good
        """
        certs = [
            autority.cert_from_issuer
            for autority in self.CA
            if autority.issuer_key.public_numbers() == issuer_key.public_numbers()
        ]
        if len(certs) != 1:
            return False
        else:
            cert = certs.pop()
            X509Certificate.verify(cert, issuer_key)
            return True

    def create_cert_chain(self, pubkey_other) -> List[X509Certificate]:
        graph = Graph([])
        for autority in self.DA:
            graph.add_edge(
                n1=autority.issuer_key.public_numbers(),
                n2=autority.cert_from_issuer.public_key().public_numbers(),
                cost=1,
                both_ends=False,
            )
        dq = graph.dijkstra(
            source=pubkey_other.public_numbers(),
            dest=self.certificate.public_key().public_numbers(),
        )
        if len(dq) <= 1:
            # no chain
            return []

        cert_chain: List[X509Certificate] = []
        n1 = dq.popleft()
        while len(dq) != 0:
            n2 = dq.popleft()

            for autority in self.DA:
                if (
                    autority.issuer_key.public_numbers() == n1
                    and autority.cert_from_issuer.public_key().public_numbers() == n2
                ):
                    cert_chain.append(autority.cert_from_issuer)
                    break
            n1 = n2
        return cert_chain

    def is_known_by_DA(self, s: socket.socket, pubkey_other) -> bool:
        cert_chain = self.create_cert_chain(pubkey_other)

        set_to_send = []
        for cert in cert_chain:
            d = cert.cert_pem().decode()
            set_to_send.append(d)

        sendall(s, json.dumps(set_to_send).encode())

        cert_chain_received = recv_json(s)
        cert_chain_received = [
            X509Certificate.load_from_pem(cert.encode()) for cert in cert_chain_received
        ]

        print("Cert chain exchanged")

        if len(cert_chain) != 0:
            print("I CAN reach the other one, no more question on my side")
            return True

        else:
            if len(cert_chain_received) == 0:
                print("NONE of us can reach the other one with a cert chain")
                return False
            else:
                # the other one a cert chain. Is it valid ?
                try:
                    X509Certificate.verify_chain(
                        self.key_pair.public_key(), cert_chain_received
                    )
                except (ValueError, NotValidCertificate) as e:
                    print(
                        "I cannot generate a cert chain and the cert chain received is NOT valid"
                    )
                    return False

        print("I cannot generate a cert chain but the cert chain received IS valid")
        return True

    def a_la_pgp_process(self, conn: socket.socket):
        """
        Define the action taken by both server and equipment.
        They do exactly the same
        """

        cert_received = self.hand_shake(conn)
        if self.is_in_CA(cert_received.public_key()):
            print("I already know you (CA)")
            self.update_DA(s=conn)
        elif self.is_known_by_DA(s=conn, pubkey_other=cert_received.public_key()):
            self.update_DA(s=conn)
            print("One of us show that we belong to the same network (DA)")
        else:
            while True:
                resp = input("Connect a new device ? (y/n)")
                if resp == "y":
                    self.update_CA(
                        s=conn,
                        subject=cert_received.issuer(),
                        pubkey=cert_received.public_key(),
                    )
                    self.update_DA(s=conn)
                    break
                elif resp == "n":
                    print("Nothing happened")
                    break
                else:
                    print("Invalid answer")

    def clean_sets(self):
        """
        clean CA and DA sets before any communications with other equipment.
        Out of date certificates are deleted
        """

        # TODO
