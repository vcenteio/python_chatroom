import time
import sys
import random
import struct
import socket
import queue
import threading
import json
import hashlib
import base64
import math
import hmac
import select
from cryptography.fernet import Fernet
from constants import *
from exceptions import *


class Message():

    ERROR, SUCCESS, UNPACK_ERROR, BROADCAST, QUERY, DISCONNECT = range(6)
    CLIENT_ID = int()

    def __init__(self, _code: int, _from: tuple, _data=None, _time=None):
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
            if msg_dict["_type"] == Command.TYPE:
                return Command(**msg_dict)
            elif msg_dict["_type"] == Reply.TYPE:
                return Reply(**msg_dict)
            # there is an error then
            else:
                raise UnknownMessageType(
                        Reply.description[Reply._UNKNOWN_MSG_TYPE]
                    )
        # integrity check failed
        else:
            raise IntegrityCheckFailed

    def __str__(self) -> str:
        return self._data
    
    def __repr__(self) -> str:
        return self.__dict__


class Command(Message):
    TYPE = "command"
    id_count = 1

    def __init__(
        self, _code: int,
        _from: tuple,
        _data=None, _id=None, _time=None, _type=None
        ):
        super().__init__(_code, _from, _data, _time)
        self._id = self.generate_id() if _id == None else _id
        self._type = self.TYPE if _type == None else _type

    @classmethod
    def generate_id(cls):
        if cls.id_count < 100000:
            _id = f"#{cls.id_count:05}@{cls.CLIENT_ID}"
            cls.id_count += 1
            return _id


class Reply(Message):
    _SUCCESSFULL_RECV, _FAILED_RECV ,_INTEGRITY_FAILURE, _UNKNOWN_MSG_TYPE, _MSG_UNPACK_ERROR = range(5)
    TYPE = "reply"
    id_count = 1

    description = {
        _SUCCESSFULL_RECV : "Message successfully received.",
        _FAILED_RECV : "Message could not be received.",
        _INTEGRITY_FAILURE : "Message did not pass integrity check.",
        _UNKNOWN_MSG_TYPE : "Message type unknown.",
        _MSG_UNPACK_ERROR : "Error unpacking message."
    }

    def __init__(
        self, _code: int,
        _from: tuple, _to, _message_id: str,
        _data=None, _id=None, _time=None, _type=None
        ):
        super().__init__(_code, _from, _data, _time)
        self._id = self.generate_id() if _id == None else _id
        self._to = _to
        self._message_id = _message_id
        self._type = self.TYPE if _type == None else _type

    @classmethod
    def generate_id(cls):
        if cls.id_count < 100000:
            _id = f"#{cls.id_count:05}"
            cls.id_count += 1
            return _id