import socket

FORMAT = "utf-8"
HEADER_SIZE = 5 
RSA_KEY = tuple()
F_KEY = bytes()

#for local testing
server_IP = socket.gethostbyname(socket.gethostname())
server_Port = 5050