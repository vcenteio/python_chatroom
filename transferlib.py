import time
import struct
import socket
import queue
import threading

class ClientCommand:
    def __init__(self, data=None):
        self.data = data
        self.time = time.asctime()
    
    CONNECT, SEND, RECEIVE, DISCONNECT = range(4)
    

class ClientReply:
    def __init__(self, data=None):
        self.data = data
        self.time = time.time()

    ERROR, SUCCESS = range(2)


def create_header(len: int):
    return struct.pack("<I", len)

def get_header(buffer: bytes):
    return struct.unpack("<I", buffer)[0]

