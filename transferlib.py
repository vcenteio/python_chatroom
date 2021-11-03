import time
import sys
import random
import struct
import socket
import queue
import threading
import json
import pickle
import hashlib
from constants import *


class Command:
    SEND, DISCONNECT, ERROR, SUCCESS = range(4)

class ClientMessage:

    def __init__(self, code: int, _from: str, data=None):
        self.code = code
        self._from = _from
        self.data = data
        self.time = time.asctime()

    def pack(self):
        serialized = json.dumps({
            'code': self.code,
            'from': self._from,
            'data': self.data
        }).encode()
        header = struct.pack("<I", len(serialized))
        hash = hashlib.sha256(serialized, usedforsecurity=True).digest()
        return header + hash + serialized



def send(socket: socket.socket, data: bytes):
    header = struct.pack("<I", len(data))
    socket.sendall(header + data)


def receive(socket: socket.socket) -> bytes:
    # receive header and unpack the message lenght
    msg_lenght = struct.unpack("<I", socket.recv(HEADER_SIZE))[0]
    # return the content of the message
    return socket.recv(msg_lenght)
