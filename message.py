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


class Message():

    CLIENT_ID = int()

    def __init__(self, _code: int, _from: str, _data=None, _time=None):
        self._code = _code
        self._from = _from
        self._data = _data
        self._time = time.asctime() if _time == None else _time
    

    def pack(self, hmac_key: bytes):
        serialized = json.dumps(self.__dict__).encode()
        msg_hash = hmac.new(hmac_key, serialized, hashlib.sha256).digest()
        return msg_hash + serialized

    @staticmethod
    def unpack(buffer: bytes, hmac_key: bytes):
        msg_hash = buffer[:HASH_SIZE] 
        msg_buffer = buffer[HASH_SIZE:] 
        new_hash = hmac.new(hmac_key, msg_buffer, hashlib.sha256).digest()
        if msg_hash == new_hash:
            msg_dict = json.loads(msg_buffer)
            if msg_dict["_code"] in range(2,5):
                return Command(**msg_dict)
            else:
                return Reply(**msg_dict)
        else:
            return False

    def __str__(self) -> str:
        return self._data
    
    def __repr__(self) -> str:
        return self.__dict__


class Command(Message):
    BROADCAST, QUERY, DISCONNECT = 2, 3, 4
    id_count = 1

    def __init__(self, _code: int, _from: str, _data=None, _id=None, _time=None):
        super().__init__(_code, _from, _data, _time)
        self._id = self.generate_id() if _id == None else _id

    @classmethod
    def generate_id(cls):
        if cls.id_count < 100000:
            _id = f"#{cls.id_count:05}@{cls.CLIENT_ID}"
            cls.id_count += 1
            return _id

class Reply(Message):
    ERROR, SUCCESS = 0, 1
    id_count = 1

    def __init__(self, _code: int, _from: str, _data=None, _id=None, _time=None):
        super().__init__(_code, _from, _data, _time)
        self._id = self.generate_id() if _id == None else _id

    @classmethod
    def generate_id(cls):
        if cls.id_count < 100000:
            _id = f"#{cls.id_count:05}"
            cls.id_count += 1
            return _id