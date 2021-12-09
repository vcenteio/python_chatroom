from logging import Logger, handlers
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
import secrets
from cryptography.fernet import Fernet
from constants import *
from exceptions import *
from enum import Enum, IntEnum, auto, unique
from dataclasses import dataclass, field
from abc import ABC, abstractclassmethod, abstractmethod, abstractstaticmethod


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
    _CONNECTION_REQUEST_FAILED = "Could not handle connection request."
    _LOST_CONNECTION_W_SRV = "Lost connection with the server."
    _INTEGRITY_FAILURE = "Integrity check failed."
    _UNKNOWN_MSG_TYPE = "Unknown message type."
    _MSG_W_NO_TYPE = "The passed dictionary has no '_type' key"
    _INVALID_MSG_CODE = "Invalid message code."
    _MSG_PACK_ERROR = "Failed to pack message."
    _MSG_UNPACK_ERROR = "error unpacking message"
    _MSG_DECRYPT_ERROR = "Error while decrypting message."
    _ERROR_NO_HANDLER_DEFINED = "An error ocurred for which "\
                                "there is no defined handler."
    _TOO_MANY_ERRORS = "Too many errors occured."


class QueueSignal(Enum):
    _terminate_thread = auto()
    _disconnect = auto()
    _shutdown = auto()


@dataclass
class Message(ABC):

    _code: int
    _from: tuple[int, str]
    _data: str = None
    _id: str = None
    _time: str = None

    @abstractclassmethod
    def generate_id(self, client_id) -> str:
        ...

    def __post_init__(self):
        if not self._id:
            self._id = self.generate_id(self._from[0])
        if not self._time:
            self._time = time.asctime()

    def __str__(self) -> str:
        return self._data


@dataclass
class Command(Message):
    _id_count: int = field(default=1, init=False)
    _nick_color: str = None
    _type: int = field(default=1)
    
    @classmethod
    def generate_id(cls, client_id) -> str:
        if cls._id_count < 100000:
            _id = f"#C{cls._id_count:08}@{client_id}"
            cls._id_count += 1
            return _id


@dataclass
class Reply(Message):
    _id_count: int = field(default=1, init=False)
    _to: int = None
    _message_id: int = None
    _type: int = field(default=2)
    
    @classmethod
    def generate_id(cls, client_id) -> str:
        if cls._id_count < 100000:
            _id = f"#R{cls._id_count:08}@{client_id}"
            cls._id_count += 1
            return _id

class MessageFactory(ABC):

    @abstractmethod
    def create(self, msg_dict: dict) -> Message:
        ...


class DictBasedMessageFactory(MessageFactory):

    def create_command(msg_dict: dict) -> Command:
        return Command(**msg_dict)

    def create_reply(msg_dict: dict) -> Reply:
        return Reply(**msg_dict)

    type_handlers = {
        Command._type : create_command,
        Reply._type : create_reply
    }

    def create(self, msg_dict: dict) -> Message:
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
                f"{ErrorDescription._UNKNOWN_MSG_TYPE} {e}"
            )

class MessageGuardian(ABC):
    message_factory: MessageFactory
    logger: Logger

    @abstractmethod
    def set_key(self, key: bytes) -> None:
        ...
    
    @abstractmethod
    def get_key(self) -> None:
        ...

    @abstractmethod
    def pack(self, message: Message) -> bytes:
        ...

    @abstractmethod
    def unpack(self, data: bytes) -> Message:
        ...
    
    @abstractstaticmethod
    def generate_key() -> bytes:
        ...


class HMACMessageGuardian(MessageGuardian):
    def __init__(self, message_factory: MessageFactory,
        hmac_key: bytes = None, logger: Logger = None):
        self.message_factory = message_factory
        self.hmac_key = hmac_key if hmac_key else self.generate_key()
        self.logger = logger

    def set_key(self, hmac_key: bytes) -> None:
        self.hmac_key = hmac_key
    
    def get_key(self) -> None:
        return self.hmac_key

    def pack(self, message: Message) -> bytes:
        try:
            serialized = json.dumps(message.__dict__).encode()
        except AttributeError as e:
            raise MessagePackError(e)
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

    @staticmethod
    def generate_key():
        return secrets.token_bytes(HASH_SIZE)