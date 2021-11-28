from logging import handlers
from message import *
from constants import *
from network_agent import NetworkAgent
from cryptographer import Cryptographer
import os
import logger


class ClientEntry:
    def __init__(
            self, socket: socket.socket, address: tuple,
            nickname: str, color: str, _id: int,
            crypt: Cryptographer
        ):
        self.socket = socket
        self.address = address
        self.nickname = nickname
        self.color = color
        self.ID = _id
        self.crypt = crypt 
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
        self.shutdown_q = queue.Queue()
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
        active = threading.Event()
        active.set()
        while active.is_set() and self.running.is_set():
            message = self.broadcast_q.get()
            if isinstance(message, Command):
                try:
                    packed_message = message.pack(self.hmac_key)
                    for client in self.clients.values():
                        encrypted_message = client.crypt.encrypt(
                            packed_message
                        )
                        self.logger.debug(
                            "Putting command into dispatch queue."
                            )
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
                    self.logger.error(
                        f"{ErrorDescription._FAILED_TO_SEND} "\
                        f"to client with ID [{client.ID}]. "\
                        f"content = {message._data}"
                    )
                    self.logger.debug(e)
                finally:
                    # time.sleep(SRV_SEND_SLEEP_TIME)
                    pass
            elif message is QueueSignal._terminate_thread:
                active.clear()
                self.logger.debug(
                    "Got terminate thread signal; "\
                        "active flag: set -> clear"
                    )
            self.broadcast_q.task_done()
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
                    encrypted_reply = client.crypt.encrypt(
                        packed_reply
                    )
                    self.logger.debug(
                        "Putting reply into dispatch queue."
                    )
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
                    self.logger.error(
                        f"{ErrorDescription._FAILED_TO_SEND_REPLY} "\
                        f"to client with ID [{client.ID}]. "\
                        f"content = {reply._data}"
                    )
                    self.logger.debug(e)
                finally:
                    # time.sleep(0.05)
                    pass
            elif reply == QueueSignal._terminate_thread:
                active.clear()
                self.logger.debug(
                    "Got terminate thread signal; "\
                        "active flag: set -> clear"
                    )
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
                        self.logger.error(
                            f"{ErrorDescription._FAILED_TO_SEND} "\
                            f"to client with ID [{client.ID}]."
                        )
                        self.logger.debug(e)
                    except CriticalTransferError as e:
                        self.logger.error(
                            f"Client with ID [{client.ID}] "\
                            "disconnected."
                        )
                        self.logger.debug(e)
                        self.disconnect_client(client)
                    finally:
                        time.sleep(SRV_SEND_SLEEP_TIME)
                else:
                    self.logger.debug(f"Item is not valid. Item = {item}")
            elif item is QueueSignal._terminate_thread:
                active.clear()
                self.logger.debug(
                    "Got terminate thread signal; "\
                        "active flag: set -> clear"
                    )

            self.dispatch_q.task_done()
        self.logger.debug("Exiting dispatch thread persistence loop.")

    def handle_incoming_message(self, client: ClientEntry, q: queue.Queue):
        errors_count = 0
        active = threading.Event()
        active.set()
        while active.is_set():
            item = q.get()
            if isinstance(item, bytes):
                try:
                    decrypted_message = client.crypt.decrypt(item)
                    message = Message.unpack(decrypted_message, self.hmac_key)
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
                                self.lock.acquire()
                                self.broadcast_q.put(message)
                                self.reply_q.put(reply)
                                self.lock.release()
                                self.logger.info(
                                    f"Broadcast command received from "\
                                    f"client with ID [{message._from[0]}], "\
                                    f"Message ID = [{message._id}], "\
                                    f"Content = '{message._data}'"
                                )
                            elif message._code == CommandType.QUERY:
                                #just print the message for now
                                print(message)
                            elif message._code == CommandType.DISCONNECT:
                                self.logger.info(
                                    f"Disconnect request received from "\
                                    f"client with ID [{message._from[0]}]."
                                )
                                self.disconnect_client(client)
                            elif message._code == CommandType.SHUTDOWN:
                                self.logger.info(
                                    f"Shutdown command received from "\
                                    f"client with ID [{message._from[0]}]."
                                    )
                                client.active.clear()
                                self.shutdown_q.put(QueueSignal._shutdown)
                        elif isinstance(message, Reply):
                            #just print the message for now
                            self.logger.info(
                                f"Reply received from client with ID "\
                                f"[{message._from[0]}], "\
                                f"Message ID = [{message._message_id}], "\
                                f"Content = '{message._data}'"
                            )
                except UnknownMessageType:
                    self.logger.error(
                        ErrorDescription._UNKNOWN_MSG_TYPE
                    )
                    reply = Reply(
                                ReplyType.ERROR,
                                (SERVER_ID, self.name),
                                client.ID,
                                "-",
                                ReplyDescription._UNKNOWN_MSG_TYPE
                            )
                    self.reply_q.put(reply)
                except (InvalidDataForEncryption, EncryptionError) as e:
                    self.logger.error(ErrorDescription._MSG_DECRYPT_ERROR)
                    self.logger.debug(e)
                except IntegrityCheckFailed:
                    self.logger.error(
                            f"{ErrorDescription._INTEGRITY_FAILURE} "\
                            f"Client ID = [{client.ID}] "\
                            f"Client nickname = [{client.nickname}]"
                    )
                    reply = Reply(
                                ReplyType.ERROR,
                                (SERVER_ID, self.name),
                                client.ID,
                                "-",
                                ReplyDescription._INTEGRITY_FAILURE
                            )
                    self.reply_q.put(reply)
                    errors_count += 1
                    if errors_count > CRITICAL_ERRORS_MAX_NUMBER:
                        self.logger.debug(
                            "Too many integrity errors. "\
                            f"Disconnecting client with ID [{client.ID}]"
                        )
                        self.disconnect_client(client)
                        active.clear()
                        time.sleep(0.1)
            elif item is QueueSignal._terminate_thread:
                self.logger.debug(
                    "Got terminate signal from the queue. "\
                    f"Client ID #[{client.ID}]"
                    )
                active.clear()
            else:
                self.logger.warning(ErrorDescription._UNKNOWN_MSG_TYPE)
            q.task_done()
        self.logger.debug(
            "Exiting persistence loop. "\
            f"Client ID #[{client.ID}]"
        )

    def handle_client(self, client: ClientEntry):
        errors_count = 0
        msg_handler_q = queue.Queue()
        msg_handler_thread = threading.Thread(
            target=self.handle_incoming_message,
            args=[client, msg_handler_q],
            name=f"{client.ID}_MSGHNDLR",
            daemon=True
        )
        msg_handler_thread.start()
        while client.active.is_set():
            try:
                buffer = self.receive(client.socket)
                msg_handler_q.put(buffer)
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
                if client.active.is_set():
                    self.logger.error(
                        f"Client with ID [{client.ID}] "\
                        "disconnected unexpectedly."
                    )
                self.disconnect_client(client)
            finally:
                time.sleep(SRV_RECV_SLEEP_TIME)
        # stop message handler thread 
        if not client.active.is_set():
            self.logger.debug(
                f"Client active flag changed: set -> clear, "\
                f"Client ID = [{client.ID}]"
            )
        self.terminate_thread(msg_handler_thread, msg_handler_q)
        time.sleep(0.2)
        self.logger.debug(
            f"Exiting handle client loop, "\
            f"Client ID = [{client.ID}]"
        )
    
    def exchange_keys_with_client(self, client_socket: socket.socket):
        self.logger.debug(
            "Starting encryption keys exchange with new client."
        )
        # send rsa public key to client
        self.logger.debug("Sending RSA public key to client.")
        self.send(
            client_socket,
            f"{self.public_key[0]}-{self.public_key[1]}".encode()
        )
        time.sleep(0.1)
        self.logger.debug("RSA public key sent.")
        # receive client public key
        self.logger.debug("Waiting for client's RSA public key.")
        buffer = self.receive(client_socket).decode().split("-")
        client_public_key = (int(buffer[0]), int(buffer[1]))
        time.sleep(0.1)
        self.logger.debug(f"Client public key: {client_public_key}")
        # encrypt fernet and HMAC keys with client's public key and send them to client
        self.logger.debug("Sending Fernet key.")
        self.send(
            client_socket,
            self.fernet_key
        )
        time.sleep(0.1)
        self.logger.debug("Fernet key sent.")
        self.logger.debug("Sending HMAC key.")
        self.send(
            client_socket,
            self.hmac_key
        )
        time.sleep(0.1)
        self.logger.debug("HMAC key sent.")
        # create client cryptographer object
        client_crypt = Cryptographer(
            self.private_key,
            client_public_key,
            self.fernet_key,
            self.logger
        )
        self.logger.debug(
            "Keys exchange terminated. "\
            "Returning client's cryptographer object."
        )
        return client_crypt 

    def exchange_setup_data_with_client(self, client_socket: socket.socket,
        client_crypt: Cryptographer, client_id: int):

        # receive client's setup data
        self.logger.debug("Waiting for client's setup data.")
        setup_data = json.loads(
            client_crypt.decrypt(
                self.receive(client_socket)
            )
        )
        self.logger.debug(
            f"Client setup data received: {setup_data}"
        )
        # send generated id number to client
        self.logger.debug(f"Sending ID #[{client_id}] to new client.")
        self.send(
            client_socket,
            client_crypt.encrypt(struct.pack("<I", client_id))
        )
        self.logger.debug("Client ID sent successfully.")
        return setup_data

    def setup_new_client(self, client_socket: socket.socket, address: tuple):
        self.logger.debug("Setting up new client.")
        # keys exchange
        client_crypt = self.exchange_keys_with_client(client_socket)
        # generate an id for the new client
        new_id = self.generate_client_id()
        self.logger.debug(f"ID #[{new_id}] generated.")
        # exchange setup data with client
        client_setup_data = self.exchange_setup_data_with_client(
            client_socket,
            client_crypt,
            new_id
            )
        # create client entry
        new_client = ClientEntry(
            client_socket,
            address,
            client_setup_data["nickname"],
            client_setup_data["color"],
            new_id,
            client_crypt 
        )
        self.logger.debug(
            "New client registry successfully created, "\
            f"Client ID=[{new_client.ID}]"
        )
        # add client to clients list
        self.clients.update({new_client.ID: new_client})
        # create client's thread
        new_client_thread = threading.Thread(
            target=self.handle_client,
            args=[new_client],
            name=new_client.ID
        )
        # add client's thread to threads list
        self.client_threads.update({
            int(new_client_thread.name): new_client_thread
        })
        # start new client's thread
        self.logger.debug(f"Starting client [{new_client.ID}] thread.")
        new_client.active.set()
        new_client_thread.start()
        self.logger.debug(f"Client thread started: {new_client_thread}")

        return new_client

    def handle_connections(self):
        while self.running.is_set():
            self.logger.info("Waiting for connections...")
            try:
                client_socket, client_address = self.socket.accept()

                self.logger.debug(f"New client connection from {client_address}")

                new_client = self.setup_new_client(client_socket, client_address)

                self.logger.info(
                    "New client connected, "\
                    f"Client ID=[{new_client.ID}]"
                )
                self.logger.debug(f"Online clients: {self.clients}")
                self.logger.debug(f"Clients threads: {self.client_threads}")

            except (OSError, CriticalTransferError) as e:
                if self.running.is_set():
                    self.logger.info("Could not handle connection request.")
                    self.logger.debug(f"Description: {e}")

    def setup_worker_threads(self):
        self.logger.debug("Setting up worker threads.")
        self.logger.debug("Starting broadcaster thread.")
        self.broadcast_enqueuer_thread = threading.Thread(
            target=self.broadcast_enqueuer,
            name="BROADCASTER"
            )
        self.broadcast_enqueuer_thread.start()
        self.logger.debug("Broadcaster thread started.")

        self.logger.debug("Starting replier thread.")
        self.reply_enqueuer_thread = threading.Thread(
            target=self.reply_enqueuer,
            name="REPLIER"
            )
        self.reply_enqueuer_thread.start()
        self.logger.debug("Replier thread started.")

        self.logger.debug("Starting dispatcher thread.")
        self.dispatch_thread = threading.Thread(
            target=self.dispatch,
            name="DISPATCHER"
            )
        self.dispatch_thread.start()
        self.logger.debug("Dispatcher thread started.")

        self.logger.debug("Starting connection handler thread.")
        self.connections_thread = threading.Thread(
            target=self.handle_connections,
            name="CONNECTION_HANDLER"
            )
        self.connections_thread.start()
        self.logger.debug("Connection handler thread started.")
        self.logger.debug("Worker threads setup finished.")

    def run(self):
        self.setup_logger()
        self.q_listener.start()
        self.address = (SERVER_IP, SERVER_PORT)
        self.logger.info(f"Starting the server @{self.address} ...")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(self.address)
        self.socket.listen()
        self.generate_fernet_key()
        self.generate_hmac_key()
        self.logger.debug(f"Public key: {self.public_key}")
        self.logger.debug(f"Fernet key: {self.fernet_key}")
        self.logger.debug(f"HMAC key: {self.hmac_key}")
        self.running.set()

        self.setup_worker_threads()
        # wait for shutdown command from a client thread
        while self.running.is_set():
            signal = self.shutdown_q.get()
            if signal is QueueSignal._shutdown:
                self.shutdown()

    def disconnect_client(self, client: ClientEntry):
        client.active.clear()
        self.logger.debug(f"Closing client socket. Client ID #[{client.ID}]")
        self.close_socket(client.socket)
        try:
            self.clients.pop(client.ID)
        except KeyError as e:
            self.logger.debug(
                f"Could not remove client from list. "\
                f"Description={e}"
            )
        self.logger.info(
            f"Client with ID #[{client.ID}] disconnected."
        )
    
    def terminate_client_thread(self, thread: threading.Thread):
        attempts = 0
        while thread.is_alive() and attempts < 4:
            try:
                thread.join()
                self.logger.debug(f"Client with thread name [{thread.name}] joined.")
            except RuntimeError:
                attempts += 1
                if attempts < 4:
                    self.logger.debug(
                        f"Client thread [{thread.name}] is still alive. "\
                        "Trying again."
                    )
                    time.sleep(1)
                else:
                    self.logger.warning(
                        "Could not join client thread. "\
                        f"Thread name = [{thread.name}] "\
                        f"Alive = [{thread.is_alive()}]"
                    )

    def disconnect_all_clients(self):
        self.logger.debug("Closing client sockets.")
        clients = tuple(self.clients.values())
        for client in clients:
            self.disconnect_client(client)
            time.sleep(0.2)
        if not self.clients:
            self.logger.debug("No clients connected.")
        else:
            self.logger.debug(
                f"Some clients could not be removed from the list. "\
                f"Active clients: {self.clients}"
            )
    
    def shutdown(self):
        self.logger.info("Server shutting down.")
        self.running.clear()
        time.sleep(2)
        # reconfig logger: queue handler -> direct file and stream handlers
        self.logger.debug("Terminating QueueListener thread.")
        self.q_listener.stop()
        self.logger.debug("QueueListener thread terminated.")
        for handler in self.logger.handlers:
            self.logger.removeHandler(handler)
        self.logger.addHandler(logger.get_stream_handler())
        self.logger.addHandler(logger.get_file_handler(self.name, "a"))
        # disconnect clients
        self.disconnect_all_clients()
        # terminate client threads
        self.logger.debug("Terminating client threads.")
        for thread in self.client_threads.values():
            self.terminate_client_thread(thread)
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
        # close server socket and connection handler thread
        self.logger.debug("Closing server's socket.")
        self.close_socket(self.socket)
        self.logger.debug("Server's socket closed.")
        self.terminate_thread(self.connections_thread)
        
        self.logger.debug(f"Threads list: {threading.enumerate()}")
        self.logger.info("Shutdown process finished. Exiting.")
        

if __name__ == "__main__":
    server = Server()
    server.start()