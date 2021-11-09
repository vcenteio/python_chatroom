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
import base64
import math
import hmac
from cryptography.fernet import Fernet
from constants import *


class Command:
    SEND, DISCONNECT, ERROR, SUCCESS = range(4)

class ClientMessage:

    id_count = 1
    CLIENT_ID = int()

    def __init__(self, code: int, _from: str, data=None, _id=None):
        self.code = code
        self._from = _from
        self.data = data
        self.id = self.generate_id() if _id == None else _id
        self.time = time.asctime()
    
    @classmethod
    def generate_id(cls):
        if cls.id_count < 100000:
            _id = f"#{cls.id_count:05}@{cls.CLIENT_ID}"
            cls.id_count += 1
            return _id

    def pack(self, hmac_key: bytes):
        serialized = json.dumps({
            'code': self.code,
            'from': self._from,
            'data': self.data,
            'id': self.id,  
            'time': self.time
        }).encode()
        msg_hash = hmac.new(hmac_key, serialized, hashlib.sha256).digest()
        return msg_hash + serialized

    @staticmethod
    def unpack(buffer: bytes, hmac_key: bytes):
        msg_hash = buffer[:HASH_SIZE] 
        msg_buffer = buffer[HASH_SIZE:] 
        new_hash = hmac.new(hmac_key, msg_buffer, hashlib.sha256).digest()
        if msg_hash == new_hash:
            msg_dict = json.loads(msg_buffer)
            return ClientMessage(msg_dict["code"], msg_dict["from"], msg_dict["data"], msg_dict["id"])
        else:
            return ClientMessage(Command.ERROR, "_server", "[SERVER] Integrity check failed.")

    def __str__(self) -> str:
        return self.data

