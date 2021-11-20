from logging import handlers
from message import *
from constants import *
from network_agent import NetworkAgent
import sys
import os
import logger

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
                self.logger.info("Could not broadcast message.")
                self.logger.debug(f"ConnectionResetError - Message ID: {message._id}.")
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
                            self.logger.info(
                                f"Broadcast command received from " +
                                f"client with ID [{message._from[0]}], " +
                                f"Message ID = [{message._id}], " +
                                f"Content = '{message._data}'"
                            )
                        elif message._code == CommandType.QUERY:
                            #just print the message for now
                            print(message)
                        elif message._code == CommandType.DISCONNECT:
                            self.logger.info(
                                f"Disconnect request received from " +
                                f"client with ID [{message._from[0]}]."
                            )
                            self.disconnect_client(client)
                        elif message._code == CommandType.SHUTDOWN:
                            self.logger.info(
                                f"Shutdown command received from " +
                                f"client with ID [{message._from[0]}]."
                                )
                            client.active.clear()
                            self.shutdown_q.put(None)
                    elif isinstance(message, Reply):
                        #just print the message for now
                        self.logger.info(
                            f"Reply received from client with ID " +
                            f"[{message._from[0]}], " +
                            f"Message ID = [{message._message_id}], " +
                            f"Content = '{message._data}'"
                        )
            # it's an error generated by the unpack function
            except IntegrityCheckFailed:
                self.logger.error(
                    ReplyDescription._INTEGRITY_FAILURE
                )
                reply = Reply(
                            ErrorType.UNPACK_ERROR,
                            (SERVER_ID, self.name),
                            client.ID,
                            "-",
                            ReplyDescription._INTEGRITY_FAILURE
                        )
                self.broadcast_q.put(reply)
            except UnknownMessageType:
                self.logger.error(
                    ReplyDescription._UNKNOWN_MSG_TYPE
                )
                reply = Reply(
                            ErrorType.UNPACK_ERROR,
                            (SERVER_ID, self.name),
                            client.ID,
                            "-",
                            ReplyDescription._UNKNOWN_MSG_TYPE
                        )
                self.broadcast_q.put(reply)
            except struct.error:
                self.logger.error(
                    f"Error unpacking message header from " +
                    f"client with ID [{client.ID}]."
                )
                reply = Reply(
                            ErrorType.UNPACK_ERROR,
                            (SERVER_ID, self.name),
                            client.ID,
                            "-",
                            ReplyDescription._MSG_UNPACK_ERROR
                        )
                self.broadcast_q.put(reply)
            except (OSError, ConnectionError) as e:
                self.logger.error(
                    f"Client ID with [{client.ID}] " +
                    "unexpectedly disconnected."
                )
                self.logger.debug(f"{e}, client ID = [{client.ID}]")
                self.logger.debug(f"Terminating thread [{client.ID}]")
                client.active.clear()
                break
            # except ConnectionError:
            #     self.logger.error("Connection Error: Terminanting thread.")
            #     client.active.clear()
            #     break
            finally:
                time.sleep(SRV_RECV_SLEEP_TIME)
                if not client.active.is_set():
                    self.logger.debug(
                        f"Client active flag changed: set -> clear, " +
                        f"Client ID = [{client.ID}]"
                    )

        self.logger.debug(
            f"Exiting handle client loop, " +
            f"Client ID = [{client.ID}]"
        )

    
    def handle_connections(self):
        self.logger.info(f"Starting the server @{self.address} ...")
        self.logger.debug(f"Public key: {self.public_key}")
        self.logger.debug(f"Fernet key: {self.fernet_key}")
        self.logger.debug(f"HMAC key: {self.hmac_key}")

        while self.running.is_set():
            self.logger.info("Waiting for connections...")
            try:
                client_socket, client_address = self.socket.accept()
            except OSError as e:
                if self.running.is_set():
                    self.logger.info("Could not handle connection request.")
                    self.logger.debug(f"Description: {e}")

            self.logger.debug(f"New client connection from {client_address}")
            self.logger.debug(
                "Starting encryption keys exchange with new client."
            )

            # send rsa public key to client
            self.logger.debug("Sending RSA public key to client.")
            self.send(
                client_socket,
                f"{self.public_key[0]}-{self.public_key[1]}".encode()
            )
            self.logger.debug("RSA public key sent.")

            # receive client public key
            self.logger.debug("Waiting for client's RSA public key.")
            buffer = self.receive(client_socket).decode().split("-")
            client_public_key = (int(buffer[0]), int(buffer[1]))
            self.logger.debug(f"Client public key: {client_public_key}")

            # encrypt fernet and HMAC keys with client's public key and sent them to client
            self.logger.debug("Sending Fernet key.")
            self.send(
                client_socket,
                self.rsa_encrypt_b(self.fernet_key, client_public_key)
            )
            self.logger.debug("Fernet key sent.")
            self.logger.debug("Sending HMAC key.")
            self.send(
                client_socket,
                self.rsa_encrypt_b(self.hmac_key, client_public_key)
            )
            self.logger.debug("HMAC key sent.")

            # receive nickname and color
            self.logger.debug("Waiting for client's initial data.")
            initial_data = json.loads(
                self.rsa_decrypt_b(
                    self.receive(client_socket), self.private_key
                )
            )
            self.logger.debug(
                f"Client initial data received: {initial_data}"
            )

            # create client entry
            new_client = ClientEntry(
                client_socket,
                client_address,
                initial_data["nickname"],
                initial_data["color"],
                self.generate_client_id(),
                client_public_key
            )

            # send generated ID
            self.logger.debug(
                f"ID {new_client.ID} generated."
            )
            self.logger.debug(f"Sending client ID.")
            self.send(
                client_socket,
                self.encrypt(
                    struct.pack("<I", new_client.ID),
                    new_client.public_key
                )
            )
            self.logger.debug(
                "New client registry successfully created, " +
                f"Client ID=[{new_client.ID}]"
            )
            self.logger.info(
                "New client connected, " +
                f"Client ID=[{new_client.ID}]"
            )

            self.clients.update({new_client.ID: new_client})
            new_client.active.set()
            self.logger.debug(f"Online clients: {self.clients}")

            new_client_thread = threading.Thread(
                target=self.handle_client,
                args=[new_client]
            )
            new_client_thread.name = new_client.ID
            self.client_threads.update({
                new_client_thread.name: new_client_thread
            })
            new_client_thread.start()
            self.logger.debug(f"Clients threads: {self.client_threads}")

    def run(self):
        self.setup_logger()
        self.q_listener.start()
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

        # listen for shutdown command from a client thread
        self.shutdown_q = queue.Queue()
        _sentinel = self.shutdown_q.get()
        if _sentinel is None:
            self.shutdown()
    
    def disconnect_client(self, client: ClientEntry):
        client.active.clear()
        try:
            client.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            client.socket.close()
        except OSError:
            self.logger.error(
                " ".join([
                    "Error closing client socket:",
                    "client socket already closed.",
                    f"Client ID=[{client.ID}]"
                ])
            )
        self.clients.pop(client.ID)
        self.logger.info(
            f"Client with ID [{client.ID}] disconnected."
        )

    def shutdown(self):
        self.logger.info("Server shutting down.")
        self.running.clear()
        time.sleep(3)

        # terminate QueueListener thread and remove QueueHandler 
        self.q_listener.stop()
        for handler in self.logger.handlers:
            self.logger.removeHandler(handler)
        
        # setup new handlers for shutdown logging
        self.logger.addHandler(logger.get_stream_handler())
        self.logger.addHandler(logger.get_file_handler(self.name, "a"))

        # disconnect clients
        self.logger.debug("Closing client connections.")
        clients = tuple(self.clients.values())
        for client in clients:
            self.disconnect_client(client)
            time.sleep(0.5)
        if not self.clients:
            self.logger.debug("No clients connected.")
        else:
            self.logger.debug(f"Active clients: {self.clients}")

        # terminate client threads
        for thread in self.client_threads.values():
            try:
                thread.join()
            except RuntimeError:
                self.logger.warning(
                    "Could not join client thread. " +
                    f"Thread name = [{thread.name}]" +
                    f"Alive = [{thread.is_alive()}]"

                )
        self.logger.debug(f"Client threads: {self.client_threads}")

        # terminate broadcast thread
        self.broadcast_q.put(1) # put dummy object and make it call taskdone()
        self.logger.debug("Waiting for broadcast queue to get empty.")
        if not self.broadcast_q.empty():
            while True:
                try:
                    _ = self.broadcast_q.get_nowait()
                    self.broadcast_q.task_done()
                    print(_)
                except queue.Empty:
                    self.logger.debug("Broadcast queue empty.")
                    break
        self.logger.debug("Joining broadcast queue.")
        self.broadcast_q.join()
        if self.broadcast_thread.is_alive():
            try:
                self.broadcast_q.join()
            except RuntimeError:
                pass
        self.logger.debug("Broadcast thread terminated.")

        # close server socket and terminate handle_connections thread
        try:
            self.socket.close()
        except OSError:
            self.logger.debug("Server socket already closed.")
        
        if self.connections_thread.is_alive():
            self.logger.debug("Waiting for connections thread to terminate.")
            try:
                self.connections_thread.join()
            except:
                pass
        self.logger.debug("Connections thread terminated.")

        self.logger.info("Shutdown process finished. Exiting.")
        self.logger.debug(f"Threads list: {threading.enumerate()}")
        

if __name__ == "__main__":
    server = Server()
    server.start()