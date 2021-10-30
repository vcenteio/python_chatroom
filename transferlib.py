import time
import struct
import socket
import queue
import threading
import json
import pickle
from constants import *


class Command:
    SEND, DISCONNECT, ERROR, SUCCESS = range(4)

class ClientMessage:

    def __init__(self, code: int, _from: str, data=None):
        self.code = code
        self._from = _from
        self.data = data
        self.packed = self.create_header() + self.serialized()
        self.time = time.asctime()

    def serialized(self) -> bytes:
        return json.dumps({'code': self.code, 'from': self._from, 'data': self.data}).encode()

    def create_header(self) -> bytes:
        return struct.pack("<I", len(self.serialized()))



# def get_header(buffer):
#     return struct.unpack("<Ib", buffer)

# def send(socket: socket.socket, packed_msg: bytes):
#     socket.sendall(packed_msg)

def receive(socket: socket.socket) -> bytes:
    # receive header and unpack the message lenght
    msg_lenght = struct.unpack("<I", socket.recv(HEADER_SIZE))[0]
    # return the content of the message
    return socket.recv(msg_lenght)
