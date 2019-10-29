"""
Overlayer of TCP socket of python by Theo & Gauthier (thus the name)
"""

import json
import socket

_END_BYTES = b"END-OF-SENDINGS"


def recv_all(s: socket.socket, flags=0) -> bytes:
    """
    Receive all until a stop string appears in the buffer.
    The endswith bytes are not necessarly at the end of packet
    """
    packet = s.recv(1024, flags)
    while _END_BYTES not in packet:
        packet += s.recv(1024, flags)

    return packet[: packet.find(_END_BYTES)]


def recv_json(s: socket.socket):
    """
    Frame the JSONDecodeError for debugging
    """
    # TODO Fix the problem where r contains only the ends of the json to received
    r = recv_all(s)
    try:
        json.loads(r)
    except json.JSONDecodeError as e:
        print(r)
        print(
            "JSONDecodeError, please try again. This equipment did nothing with corrupted data !"
        )
        raise e
    return json.loads(r)


def sendall(s: socket.socket, data: bytes, flags=0) -> None:
    """
    Basic sendall but which send specific bytes to signal the end of the message
    """
    s.sendall(data, flags)
    s.sendall(_END_BYTES, flags)
    return None
