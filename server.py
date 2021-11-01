from transferlib import *
from constants import *
import sys

class ClientEntry:
    def __init__(self, socket: socket.socket , address: tuple, nickname: str, color: str):
        self.socket = socket
        self.address = address
        self.nickname = nickname
        self.color = color
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
    
    def broadcast(self, message: ClientMessage):
        # message = ClientMessage(Command.SEND, data["from"], data["data"])
        for client in self.clients:
            self.clients[client].socket.sendall(message.pack())
                

    def handle_client(self, client: ClientEntry):
        client.active.set()
        while client.active.is_set():
            buffer = json.loads(receive(client.socket))
            message = ClientMessage(buffer["code"], buffer["from"], buffer["data"])
            # print(f"[SERVER] (Command: {message['code']}) {client.nickname}: {message['data']}")
            print(f"[SERVER] (Command: {message.code}) {message._from}: {message.data}")
            self.broadcast(message)
    
    def handle_connections(self):
        DEBUG = 0
        print(f"[SERVER] Starting the server ({server_IP}:{server_Port}) ...")
        while self.running.is_set():
            client_socket, client_address = self.socket.accept()
            print(f"New client connection: {client_address}")

            initial_data = json.loads(receive(client_socket))
            if DEBUG: print(initial_data)

            new_client = ClientEntry(
                client_socket,
                client_address,
                initial_data["nickname"],
                initial_data["color"]
            )
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