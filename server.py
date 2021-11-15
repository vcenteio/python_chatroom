﻿from message import *
from constants import *
from network_agent import NetworkAgent
import sys
import os


class ClientEntry:
    def __init__(
            self, socket: socket.socket, address: tuple,
            nickname: str, color: str, _id: int,
            public_key: tuple
        ):
        self.socket = socket
        self.address = address
        self.nickname = nickname
        self.color = color
        self.ID = _id
        self.public_key = public_key
        self.active = threading.Event()
        self.thread_id = int()
        
    def __str__(self):
        return f"({self.nickname}, {self.address})"


class Server(NetworkAgent):
    def __init__(self):
        super().__init__()
        self.name = SERVER_NAME
        self._id = SERVER_ID
        self.clients = dict()
        self.client_threads = dict() 
        self.broadcast_q = queue.Queue()
        self.lock = threading.Lock()
        self.client_id_ctrl_set = set()
    
    def generate_fernet_key(self):
        self.fernet_key = Fernet.generate_key()

    def generate_hmac_key(self):
        self.hmac_key = os.urandom(HASH_SIZE)

    def generate_client_id(self):
        while True:
            rand = random.randint(100000, 200000)
            if rand not in self.client_id_ctrl_set:
                break
        self.client_id_ctrl_set.add(rand)
        return rand

    def broadcast(self):
        while self.running.is_set():
            message = self.broadcast_q.get()
            try:
                if isinstance(message, Message):
                    if message._code == CommandType.BROADCAST:
                        for client in self.clients.values():
                            self.send(
                                client.socket,
                                self.encrypt(
                                    message.pack(self.hmac_key),
                                    client.public_key
                                )
                            )
                    elif isinstance(message, Reply):
                        self.send(
                            self.clients[message._to].socket,
                            self.encrypt(
                                message.pack(self.hmac_key),
                                self.clients[message._to].public_key
                            )
                        )
                    time.sleep(SRV_SEND_SLEEP_TIME)
            except ConnectionResetError:
                print(f"[SERVER] ConnectionsResetError - Message id: {message._id}.")
            finally:
                self.broadcast_q.task_done()

    def handle_client(self, client: ClientEntry):
        while client.active.is_set() and self.running.is_set():
            try:
                if self.can_receive_from(client.socket):
                    buffer =    self.decrypt(
                                    self.receive(client.socket),
                                    self.private_key
                                )
                else:
                    continue
                message = Message.unpack(buffer, self.hmac_key)
                if isinstance(message, Message):
                    #it's a message from the client
                    if isinstance(message, Command):
                        if message._code == CommandType.BROADCAST:
                            reply = Reply(
                                ReplyType.SUCCESS,
                                (self._id, self.name),
                                client.ID,
                                message._id,
                                ReplyDescription._SUCCESSFULL_RECV
                            )
                            self.broadcast_q.put(message)
                            self.broadcast_q.put(reply)
                            print(
                                f"[SERVER] ID: {message._id}",
                                f"{message._from[1]} (ID: {message._from[0]}):",
                                f"{message._data}"
                            )
                        elif message._code == CommandType.QUERY:
                            #just print the message for now
                            print(message)
                        elif message._code == CommandType.DISCONNECT:
                            self.disconnect_client(client)
                            print(
                                f"[SERVER] ID: {message._id}",
                                f"{message._from[1]} (ID: {message._from[0]}):",
                                f"{message._data}"
                            )
                        elif message._code == CommandType.SHUTDOWN:
                            print("[SERVER] Shutdown command received.")
                            self.shutdown()
                    elif isinstance(message, Reply):
                        #just print the message for now
                        print(
                            f"[CLIENT {message._type.upper()}]",
                            f"(Msg ID: {message._message_id})",
                            f"{message}"
                        )
            # it's an error generated by the unpack function
            except IntegrityCheckFailed:
                reply = Reply(
                            ErrorType.UNPACK_ERROR,
                            (0, self.name),
                            client.ID,
                            "-",
                            # Reply.description[Reply._INTEGRITY_FAILURE]
                            ReplyDescription._INTEGRITY_FAILURE
                        )
                self.broadcast_q.put(reply)
            except UnknownMessageType:
                reply = Reply(
                            ErrorType.UNPACK_ERROR,
                            (0, self.name),
                            client.ID,
                            "-",
                            Reply.description[Reply._UNKNOWN_MSG_TYPE]
                        )
                self.broadcast_q.put(reply)
            except struct.error:
                # self.disconnect_client(client)
                pass
            except OSError:
                pass
            except ConnectionError:
                self.disconnect_client(client)


            time.sleep(SRV_RECV_SLEEP_TIME)

    def disconnect_client(self, client: ClientEntry):
        client.active.clear()
        try:
            client.socket.shutdown(socket.SHUT_RDWR)
            client.socket.close()
        except OSError:
            print("[SERVER] Socket already closed.")
        self.clients.pop(client.ID)
        print(f"[SERVER] Client {client.nickname} (ID: {client.ID}) disconnected.")
    
    def handle_connections(self):
        DEBUG = 1
        print(f"[SERVER] Starting the server ({self.address}) ...")
        if DEBUG: print(f"[SERVER] Public key: {self.public_key}")
        if DEBUG: print(f"[SERVER] Fernet key: {self.fernet_key}")
        if DEBUG: print(f"[SERVER] HMAC key: {self.hmac_key}")

        while self.running.is_set():
            try:
                client_socket, client_address = self.socket.accept()
            except:
                break
            print(f"New client connection: {client_address}")

            # send rsa public key to client
            self.send(
                client_socket,
                f"{self.public_key[0]}-{self.public_key[1]}".encode()
            )

            # receive client public key
            buffer = self.receive(client_socket).decode().split("-")
            client_public_key = (int(buffer[0]), int(buffer[1]))

            # encrypt fernet and HMAC keys with client's public key and sent them to client
            self.send(
                client_socket,
                self.rsa_encrypt_b(self.fernet_key, client_public_key)
            )
            self.send(
                client_socket,
                self.rsa_encrypt_b(self.hmac_key, client_public_key)
            )

            # receive nickname and color
            initial_data = json.loads(
                self.rsa_decrypt_b(self.receive(client_socket), self.private_key)
            )
            if DEBUG: print(initial_data)

            # create client entry
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
            self.send(
                client_socket,
                self.encrypt(
                    struct.pack("<I", new_client.ID),
                    new_client.public_key
                )
            )

            self.clients.update({new_client.ID: new_client})
            new_client.active.set()
            if DEBUG: print(self.clients)

            new_client_thread = threading.Thread(
                target=self.handle_client,
                args=[new_client]
            )
            new_client_thread.name = new_client.ID
            self.client_threads.update({
                new_client_thread.name: new_client_thread
            })
            new_client_thread.start()
            if DEBUG: print(self.client_threads)

    def run(self):
        self.address = (SERVER_IP, SERVER_PORT)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.generate_fernet_key()
        self.generate_hmac_key()
        self.socket.bind(self.address)
        self.socket.listen()
        self.running.set()
        self.broadcast_thread = threading.Thread(target=self.broadcast)
        self.broadcast_thread.start()
        self.connections_thread = threading.Thread(target=self.handle_connections)
        self.connections_thread.start()
    
    def shutdown(self):
        DEBUG = True
        print("[SERVER] Server shutting down.")
        time.sleep(3)
        self.running.clear()

        # disconnect clients
        clients = tuple(self.clients.values())
        for client in clients:
            self.disconnect_client(client)
            try:
                self.client_threads[str(client.ID)].join()
            except RuntimeError:
                pass
            self.client_threads.pop(str(client.ID))
        if DEBUG: print(f"[SERVER] Active clients: {self.clients}")
        if DEBUG: print(f"[SERVER] Active client threads: {self.client_threads}")

        # terminate broadcast thread
        self.broadcast_q.put(1) # put dummy object and make it call taskdone()
        print("[SERVER] Waiting for broadcast_q to get empty.")
        if not self.broadcast_q.empty():
            while True:
                try:
                    _ = self.broadcast_q.get_nowait()
                    self.broadcast_q.task_done()
                    print(_)
                except queue.Empty:
                    print("[SERVER] Broadcast_q empty.")
                    break
        print("[SERVER] Joining broadcast_q.")
        self.broadcast_q.join()
        if not self.broadcast_thread.is_alive():
            print("[SERVER] Broadcast thread terminated.")
        else:
            try:
                self.broadcast_q.join()
            except RuntimeError:
                pass
            print("[SERVER] Broadcast thread terminated.")

        # close server socket and terminate handle_connections thread
        try:
            self.socket.close()
        except OSError:
            if DEBUG: print("[SERVER] Server socket already closed.")
        try: 
            if not self.connections_thread.is_alive():
                print("[SERVER] Connection handling thread terminated.")
            else:
                print("[SERVER] Waiting for the termination of connections thread.")
                self.connections_thread.join()
        except:
            print("[SERVER] Connection handling thread terminated.")

        
        print("[SERVER] Shutdown process finished. Exiting.")
        

if __name__ == "__main__":
    server = Server()
    server.start()