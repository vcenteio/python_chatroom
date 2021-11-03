import socket
import hashlib

FORMAT = "utf-8"
HEADER_SIZE = 4 
HASH_SIZE = len(hashlib.sha256().digest())
RSA_KEY = tuple()
F_KEY = bytes()

#for local testing
server_IP = socket.gethostbyname(socket.gethostname())
server_Port = 5050