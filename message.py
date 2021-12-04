from logging import handlers
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
from enum import Enum, IntEnum, auto, unique


class MessageType(IntEnum):

    def _generate_next_value_(name, start, count, last_values):
        s = __class__.__subclasses__()
        lv = []
        for subclass in s:
            lv = list(set(lv + [message.value for message in subclass]))
        if lv:
            start = lv[:].pop() + 1
        return start + count 

    def __str__(self):
        return f"{self.__class__.__name__}.{self.name}: {self.value}"
    
@unique    
class CommandType(MessageType):
    BROADCAST = auto()
    QUERY = auto()
    DISCONNECT = auto()
    SHUTDOWN = auto()

@unique
class ReplyType(MessageType):
    SUCCESS = auto()
    ERROR = auto()

@unique
class ErrorType(MessageType):
    UNPACK_ERROR = auto()
    RECEIVE_ERROR = auto()
    CONNECTION_LOST = auto()

class ReplyDescription():
    _SUCCESSFULL_RECV = "successfully received"
    _FAILED_RECV = "Message could not be received."
    _INTEGRITY_FAILURE = "did not pass integrity check"
    _UNKNOWN_MSG_TYPE = "type unknown"
    _MSG_UNPACK_ERROR = "error unpacking message"

class SuccessDescription():
    _SUCCESSFULL_SEND = "Message sent successfully."

class ErrorDescription():
    _FAILED_RECV = "Message could not be received."
    _FAILED_TO_SEND = "Message could not be sent"
    _FAILED_TO_SEND_REPLY = "Reply could not be sent"
    _FAILED_TO_HANDLE_MSG = "Message could not be handled."
    _MSG_LENGTH_ERROR = "Failed to get message length."
    _FAILED_HEADER = "Failed to prepare header for data."
    _UNABLE_TO_CONCT_W_SRV = "Could not stabilish connection with the server."
    _LOST_CONNECTION_W_SRV = "Lost connection with the server."
    _INTEGRITY_FAILURE = "Integrity check failed."
    _UNKNOWN_MSG_TYPE = "Unknown message type."
    _MSG_W_NO_TYPE = "The passed dictionary has no '_type' key"
    _INVALID_MSG_CODE = "Invalid message code."
    _MSG_UNPACK_ERROR = "error unpacking message"
    _MSG_DECRYPT_ERROR = "Error while decrypting message."
    _ERROR_NO_HANDLER_DEFINED = "An error ocurred for which "\
                                "there is no defined handler."
    _TOO_MANY_ERRORS = "Too many errors occured."

class QueueSignal(Enum):
    _terminate_thread = auto()
    _disconnect = auto()
    _shutdown = auto()


class Message():

    def __init__(self, _code: int, _from: tuple, _data=None, _time=None):
        self._code = _code
        self._from = _from
        self._data = _data
        self._time = time.asctime() if _time == None else _time

    def __str__(self) -> str:
        return self._data
    
    def __repr__(self) -> str:
        return self.__dict__


class Command(Message):
    TYPE = 1
    id_count = 1

    def __init__(
        self, _code: int,
        _from: tuple,
        _data=None, _id=None, _time=None, _type=None, _nick_color=None
        ):
        super().__init__(_code, _from, _data, _time)
        self._id = self.generate_id(_from[0]) if _id == None else _id
        self._type = self.TYPE if _type == None else _type
        self._nick_color = _nick_color

    @classmethod
    def generate_id(cls, client_id):
        if cls.id_count < 100000:
            _id = f"#{cls.id_count:05}@{client_id}"
            cls.id_count += 1
            return _id


class Reply(Message):
    TYPE = 2 
    id_count = 1

    def __init__(
        self, _code: int,
        _from: tuple, _to, _message_id: str,
        _data=None, _id=None, _time=None, _type=None
        ):
        super().__init__(_code, _from, _data, _time)
        self._id = self.generate_id() if _id == None else _id
        self._to = _to
        self._message_id = _message_id #original message id
        self._type = self.TYPE if _type == None else _type

    @classmethod
    def generate_id(cls):
        if cls.id_count < 100000:
            _id = f"#{cls.id_count:05}"
            cls.id_count += 1
            return _id


class MessageFactory():

    def create_command(msg_dict: dict) -> Command:
        return Command(**msg_dict)

    def create_reply(msg_dict: dict) -> Reply:
        return Reply(**msg_dict)

    type_handlers = {
        Command.TYPE : create_command,
        Reply.TYPE : create_reply
    }

    def create(self, msg_dict: dict):
        try:
            _type = msg_dict["_type"]
        except KeyError as e:
            raise MessageWithNoType(
                ErrorDescription._MSG_W_NO_TYPE,
                msg_dict
            )
        try: 
            return self.type_handlers[_type](msg_dict)
        except KeyError as e:
            raise UnknownMessageType(
                ErrorDescription._UNKNOWN_MSG_TYPE
                + " " + e
            )


class MessageGuardian():
    def __init__(self, hmac_key):
        self.hmac_key: bytes = hmac_key
    
    message_factory = MessageFactory()

    def pack(self, message) -> bytes:
        serialized = json.dumps(message.__dict__).encode()
        hash = hmac.new(self.hmac_key, serialized, hashlib.sha256).digest()
        return b"".join((hash, serialized))

    def unpack(self, data: bytes) -> Message:
        msg_hash = data[:HASH_SIZE] 
        msg_buffer = data[HASH_SIZE:] 
        new_hash = hmac.new(self.hmac_key, msg_buffer, hashlib.sha256).digest()
        if msg_hash == new_hash:
            msg_dict = json.loads(msg_buffer)
            return self.message_factory.create(msg_dict)
        else:
            raise IntegrityCheckFailed(
                ErrorDescription._INTEGRITY_FAILURE
            )