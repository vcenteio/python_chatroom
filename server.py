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
    
    # def broadcast(self):
    #     while self.running.is_set():
    #         # block until a new message for broadcast is a available
    #         try:
    #             print("Starting the broadcaster")
    #             message = self.broadcast_q.get() 
    #             # pack the message with header, encode it and sent to all clients
    #             packed_msg = create_header(len(message)) + message.encode()
    #             for client in self.clients:
    #                 client.socket.sendall(packed_msg)
    #         except:
    #             continue

    def broadcast(self, message):
        packed_msg = create_header(len(message)) + message.encode()
        for client in self.clients:
            client.socket.sendall(packed_msg)
                

    def handle_client(self, client: ClientEntry):
        client.active.set()

        while client.active.is_set():
            buffer = client.socket.recv(HEADER_SIZE)
            if len(buffer) == HEADER_SIZE:
                msg_lenght = get_header(buffer)
                message = client.socket.recv(msg_lenght).decode()
                print(f"{client.nickname}: {message}")
                self.broadcast_q.put(message)
                self.broadcast(message)
            else:
                print(f"[SERVER] Buffer lenght less than 4: {len(buffer)} {client.socket.fileno()} {client.socket.type} {client.socket.getblocking()}")
                client.active.clear()
                sys.exit()
    
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
    # server.running.clear()
    # sys.exit()