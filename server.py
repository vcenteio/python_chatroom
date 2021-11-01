from transferlib import *
from constants import *
import sys

class ClientEntry:
    def __init__(self, socket: socket.socket , address: tuple, nickname: str, color: str, _id: int):
        self.socket = socket
        self.address = address
        self.nickname = nickname
        self.color = color
        self.ID = _id
        self.active = threading.Event()
        
    
    def __str__(self):
        return f"({self.nickname}, {self.address})"

class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.running = threading.Event()
        self.clients = dict()
        self.broadcast_q = queue.Queue()
        self.lock = threading.Lock()
        self.client_id_ctrl_set = set()
    
    def generate_client_id(self):
        while True:
            rand = random.randint(100000, 200000)
            if rand not in self.client_id_ctrl_set:
                break
        self.client_id_ctrl_set.add(rand)
        return rand

    def broadcast(self, message: ClientMessage):
        for client in self.clients:
            self.clients[client].socket.sendall(message.pack())
                

    def handle_client(self, client: ClientEntry):
        client.active.set()
        while client.active.is_set():
            buffer = json.loads(receive(client.socket))
            message = ClientMessage(buffer["code"], buffer["from"], buffer["data"])
            # print(f"[SERVER] (Command: {message['code']}) {client.nickname}: {message['data']}")
            print(f"[SERVER] (Command: {message.code}) {message._from} (ID: {client.ID}): {message.data}")
            self.broadcast(message)
    
    def handle_connections(self):
        DEBUG = 1
        print(f"[SERVER] Starting the server ({server_IP}:{server_Port}) ...")
        while self.running.is_set():
            client_socket, client_address = self.socket.accept()
            print(f"New client connection: {client_address}")

            # receive nickname and color
            initial_data = json.loads(receive(client_socket))
            if DEBUG: print(initial_data)

            # create client
            new_client = ClientEntry(
                client_socket,
                client_address,
                initial_data["nickname"],
                initial_data["color"],
                self.generate_client_id()
            )

            # send generated ID
            if DEBUG: print(f"DEBUG: ID {new_client.ID} generated, sending ID.")
            send(client_socket, struct.pack("<I", new_client.ID))

            self.clients.update({new_client.nickname: new_client})
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