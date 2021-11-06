import socket
import hashlib
import struct

CODEC_FORMAT = "utf-8"
HEADER_FORMAT = "<I"
HEADER_SIZE =  struct.calcsize(HEADER_FORMAT)
HASH_SIZE = len(hashlib.sha256().digest())
RSA_KEY = tuple()
BYTES_SEPARATOR = b"$_-_$"
F_KEY = bytes()

#for local testing
server_IP = socket.gethostbyname(socket.gethostname())
server_Port = 5050