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
        self.dispatch_q = queue.Queue()
        self.broadcast_q = queue.Queue()
        self.reply_q = queue.Queue()
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

    def broadcast_enqueuer(self):
        while self.running.is_set():
            message = self.broadcast_q.get()
            if isinstance(message, Command):
                try:
                    packed_message = message.pack(self.hmac_key)
                    for client in self.clients.values():
                        encrypted_message = self.encrypt(
                            packed_message,
                            client.public_key
                        )
                        self.logger.debug("Putting command into dispatch queue.")
                        self.lock.acquire()
                        self.dispatch_q.put((
                            encrypted_message,
                            client 
                        ))
                        self.lock.release()
                except (
                    InvalidDataForEncryption,
                    InvalidRSAKey,
                    NullData,
                    NonBytesData
                    ) as e:
                    self.logger.error(" ".join([
                        ErrorDescription._FAILED_TO_SEND,
                        f"to client with ID [{client.ID}].",
                        f"content = {message._data}"
                    ]))
                    self.logger.debug(e)
                finally:
                    time.sleep(SRV_SEND_SLEEP_TIME)
                    self.broadcast_q.task_done()
            elif message == QueueSignal._terminate_thread:
                self.broadcast_q.task_done()
                break
        self.logger.debug("Exiting broadcast thread persistence loop.")
                
    
    def reply_enqueuer(self):
        active = threading.Event()
        active.set()
        while active.is_set() and self.running.is_set():
            reply = self.reply_q.get()
            if isinstance(reply, Reply):
                client = self.clients[reply._to]
                try:
                    packed_reply = reply.pack(self.hmac_key)
                    encrypted_reply = self.encrypt(
                        packed_reply,
                        client.public_key
                    )
                    self.logger.debug("Putting reply into dispatch queue.")
                    self.lock.acquire()
                    self.dispatch_q.put((
                        encrypted_reply,
                        client
                    ))
                    self.lock.release()
                except (
                    InvalidDataForEncryption,
                    InvalidRSAKey,
                    NullData,
                    NonBytesData
                    ) as e:
                    self.logger.error(" ".join([
                        ErrorDescription._FAILED_TO_SEND_REPLY,
                        f"to client with ID [{client.ID}].",
                        f"content = {reply._data}"
                    ]))
                    self.logger.debug(e)
                finally:
                    time.sleep(SRV_SEND_SLEEP_TIME)
            elif reply == QueueSignal._terminate_thread:
                active.clear()
            else:
                self.logger.debug("Item's type is not Reply.")
            self.reply_q.task_done()
        self.logger.debug("Exiting reply thread persistence loop.")


    def dispatch(self):
        active = threading.Event()
        active.set()
        while active.is_set() and self.running.is_set():
            item = self.dispatch_q.get()
            if isinstance(item, tuple):
                data, client = item
                if isinstance(data, bytes) \
                    and isinstance(client, ClientEntry):
                    try:
                        self.logger.debug("Sending data.")
                        self.send(client.socket, data)
                    except SendError as e:
                        self.logger.error(" ".join([
                            ErrorDescription._FAILED_TO_SEND,
                            f"to client with ID [{client.ID}]."
                        ]))
                        self.logger.debug(e)
                    except CriticalTransferError as e:
                        self.logger.error(" ".join([
                            f"Client with ID [{client.ID}]",
                            "disconnected."
                        ]))
                        self.logger.debug(e)
                        self.disconnect_client(client)
                    finally:
                        time.sleep(0.1)
                else:
                    self.logger.debug(f"Item is not valid. Item = {item}")
            elif item is QueueSignal._terminate_thread:
                    active.clear()

            self.dispatch_q.task_done()
        self.logger.debug("Exiting dispatch thread persistence loop.")

    def handle_incoming_message(self, message: Message, client: ClientEntry):
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
                    self.reply_q.put(reply)
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
                    self.shutdown_q.put(QueueSignal._shutdown)
            elif isinstance(message, Reply):
                #just print the message for now
                self.logger.info(
                    f"Reply received from client with ID " +
                    f"[{message._from[0]}], " +
                    f"Message ID = [{message._message_id}], " +
                    f"Content = '{message._data}'"
                )

    def handle_client(self, client: ClientEntry):
        errors_count = 0
        while client.active.is_set() and self.running.is_set():
            try:
                buffer = self.receive_buffer(client.socket)
                decrypted_message = self.decrypt(
                    buffer,
                    self.private_key
                )
                message = Message.unpack(decrypted_message, self.hmac_key)
                self.handle_incoming_message(message, client)

            except ReceiveError as e:
                self.logger.error(ErrorDescription._FAILED_RECV)
                self.logger.debug(e)
                reply = Reply(
                    ReplyType.ERROR,
                    (self._id, self.name),
                    client.ID,
                    "Unknown",
                    ErrorDescription._FAILED_RECV
                )
                self.reply_q.put(reply)
                errors_count += 1
                if errors_count > CRITICAL_ERRORS_MAX_NUMBER:
                    self.disconnect_client(client)
                    time.sleep(0.1)

            except CriticalTransferError as e:
                self.logger.error(" ".join([
                    f"Client with ID [{client.ID}]",
                    "disconnected unexpectedly."
                ]))
                self.disconnect_client(client)

            except IntegrityCheckFailed:
                self.logger.error(
                    " ".join([
                        ReplyDescription._INTEGRITY_FAILURE,
                        f"Client ID = [{client.ID}]",
                        f"Client nickname = [{client.nickname}]"
                    ])
                )
                reply = Reply(
                            ErrorType.UNPACK_ERROR,
                            (SERVER_ID, self.name),
                            client.ID,
                            "-",
                            ReplyDescription._INTEGRITY_FAILURE
                        )
                self.reply_q.put(reply)
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
                self.reply_q.put(reply)
            except (InvalidDataForEncryption, InvalidRSAKey) as e:
                self.logger.info("Could not receive message.")
                self.logger.debug(e)
            finally:
                if not client.active.is_set():
                    self.logger.debug(
                        f"Client active flag changed: set -> clear, " +
                        f"Client ID = [{client.ID}]"
                    )
                else:
                    time.sleep(SRV_RECV_SLEEP_TIME)

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
                continue

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

        self.broadcast_enqueuer_thread = threading.Thread(
            target=self.broadcast_enqueuer,
            name="BROADCASTER"
            )
        self.broadcast_enqueuer_thread.start()

        self.reply_enqueuer_thread = threading.Thread(
            target=self.reply_enqueuer,
            name="REPLIER"
            )
        self.reply_enqueuer_thread.start()

        self.dispatch_thread = threading.Thread(
            target=self.dispatch,
            name="DISPATCHER"
            )
        self.dispatch_thread.start()

        self.connections_thread = threading.Thread(
            target=self.handle_connections,
            name="CONNECTION_HANDLER"
            )
        self.connections_thread.start()

        # wait for shutdown command from a client thread
        self.shutdown_q = queue.Queue()
        _sentinel = self.shutdown_q.get()
        if _sentinel is QueueSignal._shutdown:
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
        try:
            self.clients.pop(client.ID)
        except KeyError as e:
            self.logger.debug(
                f"Key error while popping client from dict. "\
                f"Description={e}"
                )
        self.logger.info(
            f"Client with ID [{client.ID}] disconnected."
        )
    

    def shutdown(self):
        self.logger.info("Server shutting down.")
        self.running.clear()
        time.sleep(3)

        # terminate logger QueueListener thread and remove QueueHandler 
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
        self.terminate_thread(
            self.broadcast_enqueuer_thread,
            self.broadcast_q
        )

        # terminate reply thread
        self.terminate_thread(
            self.reply_enqueuer_thread,
            self.reply_q
        )

        # terminate dispatch thread
        self.terminate_thread(
            self.dispatch_thread,
            self.dispatch_q
        )

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