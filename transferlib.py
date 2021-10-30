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

    def __init__(self, code, _from, data=b""):
        self.code = code
        self._from = _from
        self.data = data if type(data) == bytes else data.encode()
        self.header = self.create_header()
        self.packed_msg = self.header + self.serialized
        self.time = time.asctime()

    def create_header(self):
        return struct.pack("<bI", self.code, len(self.serialized))
    
    @property
    def serialized(self):
        return json.dumps({'from': self._from, 'data': self.data.decode()}).encode()



# def get_header(buffer):
#     return struct.unpack("<Ib", buffer)

# def send(socket: socket.socket, packed_msg: bytes):
#     socket.sendall(packed_msg)

def receive(socket: socket.socket) -> tuple:
    # receive header and unpack it
    buffer = socket.recv(HEADER_SIZE)
    header = struct.unpack("<bI", buffer)

    # get the code and lenght of the message so we can receive the
    # content of the message
    code, msg_lenght = header
    message = socket.recv(msg_lenght)

    return (code, message)