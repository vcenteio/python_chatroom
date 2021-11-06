from transferlib import *
from constants import *
import sys
import os

class ClientEntry:
    def __init__(self, socket: socket.socket , address: tuple, nickname: str, color: str, _id: int, public_key: tuple):
        self.socket = socket
        self.address = address
        self.nickname = nickname
        self.color = color
        self.ID = _id
        self.active = threading.Event()
        self.public_key = public_key
        
    
    def __str__(self):
        return f"({self.nickname}, {self.address})"

class Server(NetworkAgent):
    def __init__(self, ip, port):
        super().__init__()
        self.ip = ip
        self.port = port
        self.clients = dict()
        self.broadcast_q = queue.Queue()
        self.lock = threading.Lock()
        self.client_id_ctrl_set = set()
        self.fernet_key = self.generate_fernet_key()
        self.hmac_key = os.urandom(HASH_SIZE)
    
    def generate_client_id(self):
        while True:
            rand = random.randint(100000, 200000)
            if rand not in self.client_id_ctrl_set:
                break
        self.client_id_ctrl_set.add(rand)
        return rand

    def broadcast(self, message: bytes):
        for client_ID in self.clients:
            self.send(
                self.clients[client_ID].socket,
                self.encrypt(message, self.fernet_key, self.clients[client_ID].public_key)
            )
                

    def handle_client(self, client: ClientEntry):
        client.active.set()
        while client.active.is_set():
            buffer = self.decrypt(self.receive(client.socket), self.fernet_key, self.private_key)
            message = ClientMessage.unpack(buffer)
            if message.code == Command.ERROR:
                print(message)
                self.broadcast(message.pack())
            else:
                self.broadcast(message.pack())
                print(f"[SERVER] (Command: {message.code}) {message._from} (ID: {client.ID}): {message.data}")
    
    def handle_connections(self):
        DEBUG = 1
        print(f"[SERVER] Starting the server ({server_IP}:{server_Port}) ...")
        print(f"[SERVER] Public key: {self.public_key}")
        print(f"[SERVER] Fernet key: {self.fernet_key}")
        print(f"[SERVER] HMAC key: {self.hmac_key}")
        while self.running.is_set():
            client_socket, client_address = self.socket.accept()
            print(f"New client connection: {client_address}")

            # send rsa public key to client
            self.send(client_socket, f"{self.public_key[0]}-{self.public_key[1]}".encode())

            # receive client public key
            buffer = self.receive(client_socket).decode().split("-")
            client_public_key = (int(buffer[0]), int(buffer[1]))

            # encrypt fernet and HMAC keys with client's public key and sent them to client
            self.send(client_socket, self.rsa_encrypt_b(self.fernet_key, client_public_key))
            self.send(client_socket, self.rsa_encrypt_b(self.hmac_key, client_public_key))

            # receive nickname and color
            initial_data = json.loads(self.rsa_decrypt_b(self.receive(client_socket), self.private_key))
            if DEBUG: print(initial_data)

            # create client
            new_client = ClientEntry(
                client_socket,
                client_address,
                initial_data["nickname"],
                initial_data["color"],
                self.generate_client_id(),
                client_public_key
            )
            if DEBUG: print("[SERVER] Client public key:", new_client.public_key)

            # send generated ID
            if DEBUG: print(f"DEBUG: ID {new_client.ID} generated, sending ID.")
            self.send(client_socket, self.encrypt(struct.pack("<I", new_client.ID), self.fernet_key, new_client.public_key))

            self.clients.update({new_client.ID: new_client})
            if DEBUG: print(self.clients)

            threading.Thread(
                target=self.handle_client,
                args=[new_client],
                daemon=True
            ).start()

    def run(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip, self.port))
        self.socket.listen()
        self.running.set()
        threading.Thread(target=self.handle_connections(), daemon=True).start()



if __name__ == "__main__":
    server = Server(server_IP, server_Port)
    threading.Thread(target=server.run(), daemon=True).start()