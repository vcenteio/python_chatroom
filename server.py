from logging import handlers
import secrets
from message import *
from constants import *
from network_agent import NetworkAgent
from cryptographer import Cryptographer
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

    active: bool
    thread_id: int
    errors_count = 0
        
    def __str__(self):
        return f"({self.nickname}, {self.address})"


class Server(NetworkAgent):
    def __init__(self):
        super().__init__()
        self.name = "SRV_MAIN" 
        self._id = SERVER_ID
        self.clients = dict()
        self.client_threads = dict() 
        self.dispatch_q = queue.Queue()
        self.broadcast_q = queue.Queue()
        self.reply_q = queue.Queue()
        self.shutdown_q = queue.Queue()
        self.lock = threading.Lock()
        self.client_id_ctrl_set = set()
    
    def generate_client_id(self):
        while True:
            rand = random.randint(100000, 200000)
            if rand not in self.client_id_ctrl_set:
                break
        self.client_id_ctrl_set.add(rand)
        return rand

    def broadcast_enqueuer(self):
        active = True
        while active and self.running:
            message = self.broadcast_q.get()
            if isinstance(message, Command):
                packed_message = None
                client = None
                try:
                    packed_message = self.msg_guardian.pack(message)
                    for client in self.clients.values():
                        encrypted_message = client.crypt.encrypt(
                            packed_message
                        )
                        self.logger.debug(
                            "Putting command into dispatch queue."
                            )
                        self.dispatch_q.put((
                            encrypted_message,
                            client 
                        ))
                except Exception as e:
                    self.logger.error(
                        f"{ErrorDescription._FAILED_TO_SEND} "\
                        f"to client #[{client.ID if client else None}]. "\
                        f"content = {message._data}"
                    )
                    self.handle_exceptions(
                        e,
                        client if client else None,
                        message,
                        packed_message if packed_message else None
                    )
            elif message is QueueSignal._terminate_thread:
                active = False
                self.logger.debug(
                    "Got terminate thread signal; "\
                        "active flag: set -> clear"
                    )
            self.broadcast_q.task_done()
        self.logger.debug("Exiting broadcast thread persistence loop.")
                
    def reply_enqueuer(self):
        active = True
        while active and self.running:
            reply = self.reply_q.get()
            if isinstance(reply, Reply):
                packed_reply = None
                encrypted_reply = None
                try:
                    client = self.clients[reply._to]
                    packed_reply = self.msg_guardian.pack(reply)
                    encrypted_reply = client.crypt.encrypt(
                        packed_reply
                    )
                    self.logger.debug(
                        "Putting reply into dispatch queue."
                    )
                    self.dispatch_q.put((
                        encrypted_reply,
                        client
                    ))
                except Exception as e:
                    self.logger.error(
                        f"{ErrorDescription._FAILED_TO_SEND_REPLY} "\
                        f"to client #[{client.ID if client else None}]. "\
                        f"content = {reply._data if reply else None}"
                    )
                    self.handle_exceptions(
                        e,
                        client if client else None,
                        reply,
                        packed_reply if packed_reply else None
                    )
            elif reply is QueueSignal._terminate_thread:
                active = False
                self.logger.debug(
                    "Got terminate thread signal; "\
                        "active flag: set -> clear"
                    )
            self.reply_q.task_done()
        self.logger.debug("Exiting reply thread persistence loop.")

    def dispatch(self):
        active = True
        while active and self.running:
            item = self.dispatch_q.get()
            if isinstance(item, tuple):
                data, client = item
                if isinstance(data, bytes) \
                    and isinstance(client, ClientEntry):
                    self.logger.debug("Sending data.")
                    try:
                        self.send(client.socket, data)
                    except Exception as e:
                        self.logger.error(
                            f"{ErrorDescription._FAILED_TO_SEND} "\
                            f"to client with ID [{client.ID}]."
                        )
                        self.handle_exceptions(e, client, data)
                    finally:
                        time.sleep(SRV_SEND_SLEEP_TIME)
                else:
                    self.logger.debug(f"Item is not valid. Item = {item}")
            elif item is QueueSignal._terminate_thread:
                active = False
                self.logger.debug(
                    "Got terminate thread signal; "\
                        "active flag: set -> clear"
                    )
            self.dispatch_q.task_done()
        self.logger.debug("Exiting dispatch thread persistence loop.")
    
    def handle_broadcast_command(self, command: Command):
        reply = Reply(
            ReplyType.SUCCESS,
            (self._id, self.name),
            command._from[0],
            command._id,
            ReplyDescription._SUCCESSFULL_RECV
        )
        self.broadcast_q.put(command)
        self.reply_q.put(reply)
        self.logger.info(
            f"Broadcast command received from "\
            f"client with ID [{command._from[0]}], "\
            f"Message ID = [{command._id}], "\
            f"Content = '{command._data}'"
        )

    def handle_query_command(self, command: Command):
        # to be implemented
        pass

    def handle_disconnect_command(self, command: Command):
        self.logger.info(
            f"Disconnect request received from "\
            f"client with ID [{command._from[0]}]."
        )
        client = self.clients[command._from[0]]
        self.disconnect_client(client)

    def handle_shutdown_command(self, command: Command):
        self.logger.info(
            f"Shutdown command received from "\
            f"client with ID [{command._from[0]}]."
            )
        self.shutdown_q.put(QueueSignal._shutdown)

    def handle_success_reply(self, reply: Reply):
        #just print the message for now
        self.logger.info(
            f"Reply received from client with ID "\
            f"[{reply._from[0]}], "\
            f"Message ID = [{reply._message_id}], "\
            f"Content = '{reply._data}'"
        )

    def handle_error_reply(self, reply: Reply):
        #just print the message for now
        self.logger.info(
            f"Reply received from client with ID "\
            f"[{reply._from[0]}], "\
            f"Message ID = [{reply._message_id}], "\
            f"Content = '{reply._data}'"
        )

    def handle_pack_error(self, e: Exception, c: ClientEntry, *args):
        message = args[0]
        self.logger.error(
            f"{ErrorDescription._MSG_PACK_ERROR} "\
            f"Message = {message} "\
            f"Description: {e}"
        )

    def handle_unknown_message_type(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(
            f"{e.__class__.__name__}: "\
            f"{ErrorDescription._UNKNOWN_MSG_TYPE} "\
            f"Messagetype = {e.args[1]}"
        )
        reply = Reply(
                    ReplyType.ERROR,
                    (self._id, self.name),
                    c.ID,
                    None,
                    _data=ErrorDescription._UNKNOWN_MSG_TYPE
                )
        self.reply_q.put(reply)
    
    def handle_message_with_no_type(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(ErrorDescription._MSG_W_NO_TYPE)
        self.logger.debug(e)
    
    def handle_encryption_error(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(ErrorDescription._MSG_DECRYPT_ERROR)
        self.logger.debug(e)
        if c:
            c.errors_count += 1
            if c.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
                self.logger.debug(
                    "Too many encryption errors. "\
                    f"Disconnecting client with ID [{c.ID}]"
                )
                self.disconnect_client(c)
                time.sleep(0.1)

    def handle_integrity_fail(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(
                f"{ErrorDescription._INTEGRITY_FAILURE} "\
                f"Client ID = [{c.ID}] "
        )
        reply = Reply(
                    ReplyType.ERROR,
                    (self._id, self.name),
                    c.ID,
                    None, 
                    ReplyDescription._INTEGRITY_FAILURE
                )
        self.reply_q.put(reply)
        c.errors_count += 1
        if c.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
            self.logger.debug(
                "Too many integrity errors. "\
                f"Disconnecting client with ID [{c.ID}]"
            )
            self.disconnect_client(c)
            time.sleep(0.1)
    
    def handle_invalid_message_code(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(
            f"{ErrorDescription._INVALID_MSG_CODE} "\
            f"Message code = {args[1]._code} "\
            f"Client ID = [{c.ID}]"
        )

    def handle_send_error(self, e: Exception, c: ClientEntry, *args):
        message = args[0]
        self.logger.debug(
            f"Could not send message '{message}', "\
            f"Client ID [{c.ID}], "\
            f"Description: {e}"
        )
    
    def handle_receive_error(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(ErrorDescription._FAILED_RECV)
        self.logger.debug(e)
        reply = Reply(
            ReplyType.ERROR,
            (self._id, self.name),
            c.ID,
            None,
            ErrorDescription._FAILED_RECV
        )
        self.reply_q.put(reply)
        c.errors_count += 1
        if c.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
            self.logger.debug(ErrorDescription._TOO_MANY_ERRORS)
            self.disconnect_client(c)
            time.sleep(0.1)

    def handle_critical_error(self, e: Exception, c: ClientEntry, *args):
        if c:
            if c.active:
                self.logger.error(
                    f"Client with ID [{c.ID}] "\
                    "disconnected unexpectedly."
                )
                self.logger.debug(f"Description: {e}")
            self.disconnect_client(c)
    
    def handle_bad_connect_request(self, e: Exception, c: ClientEntry, *args):
        if self.running:
            self.logger.info(ErrorDescription._CONNECTION_REQUEST_FAILED)
            self.logger.debug(f"Description: {e}")

    def handle_no_error_handler(self, e: Exception, c: ClientEntry, *args):
        self.logger.debug("".join((
            ErrorDescription._ERROR_NO_HANDLER_DEFINED,
            f" Error class: {e.__class__.__name__}",
        )))
        self.logger.exception(e)
        if c:
            c.errors_count += 1
            if c.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
                self.logger.debug(ErrorDescription._TOO_MANY_ERRORS)
                self.disconnect_client(c)
                time.sleep(0.1)

    message_handlers = {
        CommandType.BROADCAST : handle_broadcast_command,
        CommandType.QUERY : handle_query_command,
        CommandType.DISCONNECT : handle_disconnect_command,
        CommandType.SHUTDOWN : handle_shutdown_command,
        ReplyType.SUCCESS : handle_success_reply,
        ReplyType.ERROR : handle_error_reply
    }

    error_handlers = {
        MessagePackError.__name__ : handle_pack_error,
        UnknownMessageType.__name__ : handle_unknown_message_type,
        MessageWithNoType.__name__ : handle_message_with_no_type,
        InvalidDataForEncryption.__name__ : handle_encryption_error,
        InvalidRSAKey.__name__ : handle_encryption_error,
        NullData.__name__ : handle_encryption_error,
        NonBytesData.__name__ : handle_encryption_error,
        EncryptionError.__name__ : handle_encryption_error,
        IntegrityCheckFailed.__name__ : handle_integrity_fail,
        KeyError.__name__ : handle_invalid_message_code,
        ReceiveError.__name__ : handle_receive_error,
        CriticalTransferError.__name__ : handle_critical_error,
        OSError.__name__: handle_bad_connect_request,
        0 : handle_no_error_handler
    }

    def handle_exceptions(self, e: Exception, *args):
        err = e.__class__.__name__
        self.logger.debug(
            f"{err} exception raised. "\
            f"Sending to handler."
        )
        if err in self.error_handlers:
            self.error_handlers[err](self, e, *args)
        else:
            self.error_handlers[0](self, e, *args)

    def handle_incoming_message(self, client: ClientEntry, q: queue.Queue):
        active = True
        while active:
            item = q.get()
            if isinstance(item, bytes):
                decrypted_msg = None
                message = None
                try:
                    decrypted_msg = client.crypt.decrypt(item)
                    message = self.msg_guardian.unpack(decrypted_msg)
                    self.message_handlers[message._code](self, message)
                except Exception as e:
                    self.logger.error(ErrorDescription._FAILED_TO_HANDLE_MSG)
                    args = (decrypted_msg, message)
                    self.handle_exceptions(e, *args)
            elif item is QueueSignal._terminate_thread:
                self.logger.debug(
                    "Got terminate signal from the queue. "\
                    f"Client ID #[{client.ID}]"
                    )
                active = False
            else:
                self.logger.warning(
                    f"Got an unexpected item from the queue: {item}"
                )
            q.task_done()
        self.logger.debug(
            "Exiting persistence loop. "\
            f"Client ID #[{client.ID}]"
        )

    def handle_client(self, client: ClientEntry):
        msg_handler_q = queue.Queue()
        msg_handler_thread = threading.Thread(
            target=self.handle_incoming_message,
            args=[client, msg_handler_q],
            name=f"{client.ID}_MSGHNDLR",
            daemon=True
        )
        msg_handler_thread.start()
        while client.active:
            buffer = None
            try:
                buffer = self.receive(client.socket)
                msg_handler_q.put(buffer)
            except Exception as e:
                self.logger.error(ErrorDescription._FAILED_RECV)
                self.handle_exceptions(e, client, buffer)
            finally:
                time.sleep(SRV_RECV_SLEEP_TIME)
        # stop message handler thread 
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
        self.lock.acquire()
        # send an encapuslated temporary fernet key to client
        temp_key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        prefix = base64.urlsafe_b64encode(secrets.token_bytes(DUMMY_BYTES_SIZE))
        sufix = base64.urlsafe_b64encode(secrets.token_bytes(DUMMY_BYTES_SIZE))
        encapsulated_key = prefix + temp_key + sufix
        self.logger.debug(
            "Sending temporary fernet key. "\
            f"Key = [{temp_key}]"
        )
        self.send(client_socket, encapsulated_key)
        time.sleep(0.1)
        # send rsa public key to client
        temp_fernet = Fernet(temp_key)
        enc_rsa_key = temp_fernet.encrypt(
            base64.urlsafe_b64encode(
                f"{self.public_key[0]}-{self.public_key[1]}".encode()
            )
        )
        self.logger.debug("Sending RSA public key to client.")
        self.send(client_socket, enc_rsa_key)
        time.sleep(0.1)
        self.logger.debug("RSA public key sent.")

        # receive client public key
        self.logger.debug("Waiting for client's RSA public key.")
        key = base64.urlsafe_b64decode(
            temp_fernet.decrypt(
                self.receive(client_socket)
            )
        ).decode().split("-")
        client_public_key = (int(key[0]), int(key[1]))
        self.logger.debug(f"Client public key: {client_public_key}")
        time.sleep(0.1)

        # create temporary crypt object
        temp_crypt = Cryptographer(
            self.private_key,
            client_public_key,
            temp_key,
            self.logger
        )

        # encrypt fernet and HMAC keys with client's public key and send them
        self.logger.debug("Sending Fernet key.")
        self.send(client_socket, temp_crypt.encrypt(self.fernet_key))
        self.logger.debug("Fernet key sent.")
        time.sleep(0.1)
        self.logger.debug("Sending HMAC key.")
        self.send(client_socket, temp_crypt.encrypt(self.hmac_key))
        self.logger.debug("HMAC key sent.")
        time.sleep(0.1)

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
        self.lock.release()
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
            name=f"{new_client.ID}_HANDLER"
        )
        # add client's thread to threads list
        self.client_threads.update({
            int(new_client_thread.name.split("_")[0]): new_client_thread
        })
        # start new client's thread
        self.logger.debug(f"Starting client [{new_client.ID}] thread.")
        new_client.active = True
        new_client_thread.start()
        self.logger.debug(f"Client thread started: {new_client_thread}")

        return new_client

    def handle_connections(self):
        while self.running:
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
            except Exception as e:
                if self.running:
                    self.logger.error(ErrorDescription._CONNECTION_REQUEST_FAILED)
                self.handle_exceptions(e, None)

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
        self.fernet_key = Cryptographer.generate_fernet_key()
        self.hmac_key = MessageGuardian.generate_hmac_key()
        self.msg_guardian = MessageGuardian(self.hmac_key)
        self.logger.debug(f"Public key: {self.public_key}")
        self.logger.debug(f"Fernet key: {self.fernet_key}")
        self.logger.debug(f"HMAC key: {self.hmac_key}")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(self.address)
        self.socket.listen()
        self.running = True
        self.setup_worker_threads()
        # wait for shutdown command from a client thread
        while self.running:
            signal = self.shutdown_q.get()
            if signal is QueueSignal._shutdown:
                self.shutdown()
            else:
                self.logger.debug("Got a invalid shutdown signal.")
            self.shutdown_q.task_done()

    def disconnect_client(self, client: ClientEntry):
        client.active = False 
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
        self.running = False
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