﻿import socket
import hashlib
import struct
import base64
import logging

SERVER_NAME = "SERVER"
SERVER_ID = 1
SYSTEM_NAME = "system"
SYSTEM_ID = 2
CODEC_FORMAT = "utf-8"
HEADER_FORMAT = "<I"
HEADER_SIZE =  struct.calcsize(HEADER_FORMAT)
RECV_BLOCK_SIZE = 64
HASH_SIZE = len(hashlib.sha256().digest())
BYTES_SEPARATOR = b"$_-_$"
DUMMY_BYTES_SIZE = 2048
DUMMY_ENCODED_SIZE = len(base64.urlsafe_b64encode(bytes(DUMMY_BYTES_SIZE))) 
FERNET_KEY_SIZE = len(base64.urlsafe_b64encode(bytes(32)))
SRV_SEND_SLEEP_TIME = 0.2
SRV_RECV_SLEEP_TIME = 0
CLT_SEND_SLEEP_TIME = 0.5
CLT_RECV_SLEEP_TIME = 0
LOG_LEVEL = logging.DEBUG
LOG_FILE_MODE = "w"
CRITICAL_ERRORS_MAX_NUMBER = 2

#for local testing
SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5050