from transferlib import *
from constants import *
import sys

class ClientEntry:
    def __init__(self, socket: socket.socket , address: tuple, nickname: str):
        self.socket = socket
        self.address = address
        self.nickname = nickname
        self.active = threading.Event()

class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.running = threading.Event()
        self.clients = []
        self.broadcast_q = queue.Queue()
        self.lock = threading.Lock()
    
    def broadcast(self, data: dict):
        message = ClientMessage(Command.SEND, data["from"], data["data"])
        for client in self.clients:
            client.socket.sendall(message.packed_msg)
                

    def handle_client(self, client: ClientEntry):
        client.active.set()
        while client.active.is_set():
            code, message = receive(client.socket)
            message = json.loads(message)
            print(f"[SERVER] (Command: {code}) {message['from']}: {message['data']}")
            self.broadcast(message)
    
    def handle_connections(self):
        print("Starting the server")
        while self.running.is_set():
            client_socket, client_address = self.socket.accept()
            print(f"New client connection: {client_address}")
            new_client = ClientEntry(client_socket, client_address, "vitor")
            self.clients.append(new_client)
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