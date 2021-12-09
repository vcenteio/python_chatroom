﻿from logging import handlers, LogRecord
from message import *
from constants import *
from transfer import NetworkDataTransferer, TCPIPv4DataTransferer
from cryptographer import Cryptographer, RSAFernetCryptographer
import logger


class ClientEntry:
    def __init__(
            self, transfer_agent: NetworkDataTransferer,
            address: tuple, nickname: str, color: str, _id: int,
            crypt: Cryptographer
        ):
        self.transfer = transfer_agent
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


class Server(threading.Thread):
    def __init__(self,
    data_transferer: NetworkDataTransferer = None,
    cryptographer: Cryptographer = None
    ):
        super().__init__()
        self.transfer = data_transferer
        self.crypt = cryptographer

    name = "SRV_MAIN" 
    _id = SERVER_ID
    clients = dict()
    client_threads = dict() 
    dispatch_q = queue.Queue()
    broadcast_q = queue.Queue()
    reply_q = queue.Queue()
    shutdown_q = queue.Queue()
    lock = threading.Lock()
    client_id_ctrl_set = set()
    address: tuple 
    running: bool
    hmac_key: bytes
    logging_q = queue.Queue()

    def generate_client_id(self):
        while True:
            rand = random.randint(100000, 200000)
            if rand not in self.client_id_ctrl_set:
                break
        self.client_id_ctrl_set.add(rand)
        return rand

    def exception_filter(self, record: LogRecord):
        if "Traceback" in record.msg:
            return False
        return True

    def setup_logger(self):
        self.logger = logger.get_new_logger(self.name)
        self.logger.addHandler(
            handlers.QueueHandler(self.logging_q)
        )
        stream_handler = logger.get_stream_handler()
        stream_handler.addFilter(self.exception_filter)
        file_handler = logger.get_file_handler(self.name)
        self.q_listener = handlers.QueueListener(
            self.logging_q,
            stream_handler,
            file_handler
        )
        self.q_listener.respect_handler_level = True

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
                        self.lock.acquire()
                        client.transfer.send(data)
                        self.lock.release()
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
            ReplyDescription._SUCCESSFULL_RECV,
            _to=command._from[0],
            _message_id=command._id,
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
                    ErrorDescription._UNKNOWN_MSG_TYPE,
                    _to=c.ID
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
                f"Client ID = [{c.ID if c else None}] "
        )
        reply = Reply(
                    ReplyType.ERROR,
                    (self._id, self.name),
                    ReplyDescription._INTEGRITY_FAILURE,
                    _to=c.ID
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
                    ErrorDescription._FAILED_RECV,
                    _to=c.ID,
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
                buffer = client.transfer.receive()
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
    
    def exchange_keys_with_client(self, transfer_agent: NetworkDataTransferer):
        self.logger.debug("Begining keys exchange with client.")
        self.lock.acquire()
        client_crypt = self.crypt
        transfer_agent.send(client_crypt.export_encryption_keys())
        time.sleep(0.1)
        client_crypt.import_decryption_keys(transfer_agent.receive())
        time.sleep(0.1)
        transfer_agent.send(client_crypt.encrypt(self.hmac_key))
        self.lock.release()
        self.logger.debug("Keys exchange finished.")
        return client_crypt

    def exchange_setup_data_with_client(
        self, transfer_agent: NetworkDataTransferer,
        client_crypt: Cryptographer, client_id: int
        ):
        self.lock.acquire()
        # receive client's setup data
        self.logger.debug("Waiting for client's setup data.")
        setup_data = json.loads(
            client_crypt.decrypt(
                transfer_agent.receive()
            )
        )
        self.logger.debug(
            f"Client setup data received: {setup_data}"
        )
        # send generated id number to client
        self.logger.debug(f"Sending ID #[{client_id}] to new client.")
        transfer_agent.send(
            client_crypt.encrypt(struct.pack("<I", client_id))
        )
        self.lock.release()
        self.logger.debug("Client ID sent successfully.")
        return setup_data

    def setup_new_client(self, client_socket: socket.socket, address: tuple):
        self.logger.debug("Setting up new client.")
        # keys exchange
        client_transfer_agent = self.transfer.__class__(client_socket, self.logger)
        client_crypt = self.exchange_keys_with_client(client_transfer_agent)
        # generate an id for the new client
        new_id = self.generate_client_id()
        self.logger.debug(f"ID #[{new_id}] generated.")
        # exchange setup data with client
        client_setup_data = self.exchange_setup_data_with_client(
            client_transfer_agent,
            client_crypt,
            new_id
            )
        # create client entry
        new_client = ClientEntry(
            client_transfer_agent,
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
                client_socket, client_address = self.transfer._socket.accept()
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
        self.transfer.logger = self.logger
        self.crypt.logger = self.logger
        self.q_listener.start()
        self.address = (SERVER_IP, SERVER_PORT)
        self.logger.info(f"Starting the server @{self.address} ...")
        self.hmac_key = MessageGuardian.generate_hmac_key()
        self.msg_guardian = MessageGuardian(self.hmac_key)
        self.logger.debug(f"hmac key: {self.hmac_key}")
        self.transfer._socket.bind(self.address)
        self.transfer._socket.listen()
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
        client.transfer.close_socket()
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
    
    def consume_queue(self, q: queue.Queue, thread_name):
        try:
            while not q.empty:
                _ = q.get()
                self.logger.debug(f"Queue item: {_}")
                q.task_done()
        except queue.Empty:
            pass
        self.logger.debug(f"{thread_name} queue consumed.")

    def terminate_thread(self, t: threading.Thread, q: queue.Queue = None):
        tn = t.name.lower()
        if q:
            if t.is_alive():
                self.logger.debug(f"Sent terminate command to {tn} queue.")
                q.put(QueueSignal._terminate_thread) 
                time.sleep(0.3)
                self.logger.debug(f"Joining {tn} queue.")
                if q.unfinished_tasks:
                    self.logger.debug(f"Unfinished tasks: {q.unfinished_tasks}")
                    self.consume_queue(q, tn)
                q.join()
                self.logger.debug(f"{tn} queue joined.")
        if t.is_alive():
            try:
                self.logger.debug(f"Joining {tn} thread.")
                t.join()
                self.logger.debug(f"{tn} thread joined.")
            except RuntimeError:
                pass
        self.logger.debug(f"{t.name.lower()} thread terminated.")

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
        self.transfer.close_socket()
        self.logger.debug("Server's socket closed.")
        self.terminate_thread(self.connections_thread)
        
        self.logger.debug(f"Threads list: {threading.enumerate()}")
        self.logger.info("Shutdown process finished. Exiting.")
        

if __name__ == "__main__":
    server = Server(
        data_transferer=TCPIPv4DataTransferer(),
        cryptographer=RSAFernetCryptographer()
    )
    server.start()