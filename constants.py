import socket
import hashlib
import struct

SERVER_NAME = "SERVER"
SERVER_ID = 1
SYSTEM_NAME = "system"
SYSTEM_ID = 2
CODEC_FORMAT = "utf-8"
HEADER_FORMAT = "<I"
HEADER_SIZE =  struct.calcsize(HEADER_FORMAT)
RECV_BLOCK_SIZE = 64
HASH_SIZE = len(hashlib.sha256().digest())
RSA_KEY = tuple()
BYTES_SEPARATOR = b"$_-_$"
F_KEY = bytes()
SRV_SEND_SLEEP_TIME = 0.5
SRV_RECV_SLEEP_TIME = 0.1
CLT_SEND_SLEEP_TIME = 0.5
CLT_RECV_SLEEP_TIME = 0.1

#for local testing
SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5050