from constants import *
from message import *
from logging import handlers
from transfer import NetworkDataTransferer, TCPIPv4DataTransferer
from cryptographer import Cryptographer, RSAFernetCryptographer
from workers import Worker
from dataclasses import dataclass
from copy import copy
from threading import Thread, Lock
from queue import Queue, Empty
import threading
import logger
import random
import struct


@dataclass
class ClientEntry:

    _id: int
    address: tuple[str, int]
    nickname: str
    color: str
    transfer: NetworkDataTransferer
    crypt: Cryptographer
    msg_guardian: MessageGuardian

    def __post_init__(self):
        self.active: bool = False
        self.errors_count: int = 0
        
    def is_active(self):
        return self.active
    
    def set_state(self, *, active=True):
        self.active = active

    def __str__(self):
        return f"({self.nickname}, {self.address})"


class Server(Thread):
    def __init__(self,
        data_transferer: NetworkDataTransferer,
        cryptographer: Cryptographer,
        msg_guardian: MessageGuardian
    ):
        super().__init__()
        self.transfer = data_transferer
        self.crypt = cryptographer
        self.msg_guardian = msg_guardian

    name = "SRV_MAIN" 
    _id = SERVER_ID
    clients = dict()
    client_threads = dict() 
    dispatch_q = Queue()
    broadcast_q = Queue()
    reply_q = Queue()
    shutdown_q = Queue()
    lock = Lock()
    client_id_ctrl_set = set()
    address: tuple 
    running: bool
    logging_q = Queue()

    def generate_client_id(self):
        while True:
            rand = random.randint(100000, 200000)
            if rand not in self.client_id_ctrl_set:
                break
        self.client_id_ctrl_set.add(rand)
        return rand


    def setup_logger(self):
        self.logger = logger.get_new_logger(self.name)
        self.logger.addHandler(
            handlers.QueueHandler(self.logging_q)
        )
        stream_handler = logger.get_stream_handler()
        file_handler = logger.get_file_handler(self.name)
        self.q_listener = handlers.QueueListener(
            self.logging_q,
            stream_handler,
            file_handler
        )
        self.q_listener.respect_handler_level = True

    @Worker
    def broadcast_enqueuer(self, message):
        if isinstance(message, Command):
            try:
                packed_message = None
                client: ClientEntry = None
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
                    f"to client #[{client._id if client else None}]. "\
                    f"content = {message._data}"
                )
                self.handle_exceptions(
                    e,
                    client if client else None,
                    message,
                    packed_message if packed_message else None
                )
    @Worker 
    def reply_enqueuer(self, reply):
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
                    f"to client #[{client._id if client else None}]. "\
                    f"content = {reply._data if reply else None}"
                )
                self.handle_exceptions(
                    e,
                    client if client else None,
                    reply,
                    packed_reply if packed_reply else None
                )
    @Worker
    def dispatch(self, item):
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
                        f"to client with ID [{client._id}]."
                    )
                    self.handle_exceptions(e, client, data)
                finally:
                    time.sleep(SRV_SEND_SLEEP_TIME)
            else:
                self.logger.debug(f"Item is not valid. Item = {item}")
    
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

    def handle_wrong_type_error(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(e)

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
                    _to=c._id
                )
        self.reply_q.put(reply)
    
    def handle_message_with_no_type(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(ErrorDescription._MSG_W_NO_TYPE)
        self.logger.debug(e)
    
    def handle_encryption_error(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(ErrorDescription._CRYPTOGRAPHER_ERROR)
        self.logger.debug(e)
        if c and c.is_active():
            c.errors_count += 1
            if c.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
                self.logger.debug(
                    "Too many encryption errors. "\
                    f"Disconnecting client with ID [{c._id}]"
                )
                self.disconnect_client(c)
                time.sleep(0.1)
    
    def handle_guardian_error(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(e)
        given_args = args if args else None
        self.logger.debug(f"Client ID [{c._id}] ; Args: {given_args}")

    def handle_integrity_fail(self, e: Exception, c: ClientEntry, *args):
        if c and c.is_active():
            c.errors_count += 1
            self.logger.error(
                    f"{ErrorDescription._INTEGRITY_FAILURE} "\
                    f"Client ID = [{c._id if c else None}] "
            )
            self.logger.debug(e)
            reply = Reply(
                        ReplyType.ERROR,
                        (self._id, self.name),
                        ReplyDescription._INTEGRITY_FAILURE,
                        _to=c._id
                    )
            self.reply_q.put(reply)
            if c.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
                self.logger.debug(
                    "Too many integrity errors. "\
                    f"Disconnecting client with ID [{c._id}]"
                )
                self.disconnect_client(c)
                time.sleep(0.1)
    
    def handle_invalid_message_code(self, e: Exception, c: ClientEntry, *args):
        self.logger.error(
            f"{ErrorDescription._INVALID_MSG_CODE} "\
            f"Message code = {args[1]._code} "\
            f"Client ID = [{c._id}]"
        )

    def handle_send_error(self, e: Exception, c: ClientEntry, *args):
        message = args[0]
        self.logger.debug(
            f"Could not send message '{message}', "\
            f"Client ID [{c._id}], "\
            f"Description: {e}"
        )
    
    def handle_receive_error(self, e: Exception, c: ClientEntry, *args):
        if c.is_active():
            c.errors_count += 1
            self.logger.error(ErrorDescription._FAILED_RECV)
            self.logger.debug(e)
            reply = Reply(
                        ReplyType.ERROR,
                        (self._id, self.name),
                        ErrorDescription._FAILED_RECV,
                        _to=c._id,
                    )
            self.reply_q.put(reply)
            if c.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
                    self.logger.error(ErrorDescription._TOO_MANY_ERRORS)
                    self.disconnect_client(c)
                    time.sleep(0.1)

    def handle_critical_error(self, e: Exception, c: ClientEntry, *args):
        if c and c.is_active():
            self.logger.error(
                f"Client with ID [{c._id}] "\
                "disconnected unexpectedly."
            )
            self.logger.debug(f"{e}. Args: {args if args else None}")
            self.disconnect_client(c)
    
    def handle_bad_connect_request(self, e: Exception, c: ClientEntry, *args):
        if self.running:
            self.logger.info(ErrorDescription._CONNECTION_REQUEST_FAILED)
            self.logger.debug(f"Description: {e}")

    def handle_no_error_handler(self, e: Exception, c: ClientEntry, *args):
        self.logger.debug("".join((
            ErrorDescription._ERROR_NO_HANDLER_DEFINED,
            f" Error class: {e.__class__.__name__}. ",
            f"Args: {args}"
        )))
        self.logger.exception(e)
        if isinstance(c, ClientEntry):
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
        NonBytesData.__name__ : handle_wrong_type_error,
        EncryptionError.__name__ : handle_encryption_error,
        MessagePackError.__name__ : handle_guardian_error,
        MessageUnpackError.__name__ : handle_guardian_error,
        IntegrityCheckFailed.__name__ : handle_integrity_fail,
        KeyError.__name__ : handle_invalid_message_code,
        ReceiveError.__name__ : handle_receive_error,
        SendError.__name__ : handle_send_error,
        CriticalTransferError.__name__ : handle_critical_error,
        OSError.__name__: handle_bad_connect_request,
        0 : handle_no_error_handler
    }

    def handle_exceptions(self, e: Exception, *args):
        err = e.__class__.__name__
        if self.running:
            self.logger.debug(
                f"{err} exception raised. "\
                f"Sending to handler."
            )
        if err in self.error_handlers:
            self.error_handlers[err](self, e, *args)
        else:
            self.error_handlers[0](self, e, *args)

    @Worker
    def handle_incoming_message(self, message, client: ClientEntry):
        if isinstance(message, bytes):
            decrypted_msg = None
            try:
                decrypted_msg = client.crypt.decrypt(message)
                message = self.msg_guardian.unpack(decrypted_msg)
                self.message_handlers[message._code](self, message)
            except Exception as e:
                self.logger.error(ErrorDescription._FAILED_TO_HANDLE_MSG)
                args = (decrypted_msg, message)
                self.handle_exceptions(e, client, *args)
        else:
            self.logger.warning(
                f"Got an unexpected item from the queue: {message}"
            )

    def handle_client(self, client: ClientEntry):
        msg_handler_q = Queue()
        msg_handler_thread = Thread(
            target=self.handle_incoming_message,
            args=(self, msg_handler_q, self.logger, client),
            name=f"{client._id}_MSGHNDLR",
            daemon=True
        )
        msg_handler_thread.start()
        while client.is_active():
            buffer = None
            try:
                buffer = client.transfer.receive()
                msg_handler_q.put(buffer)
            except Exception as e:
                if client.is_active():
                    self.logger.error(ErrorDescription._FAILED_RECV)
                    self.handle_exceptions(e, client, buffer)
            finally:
                time.sleep(SRV_RECV_SLEEP_TIME)
        self.logger.debug(
            f"Client active flag changed: set -> clear, "\
            f"Client ID = [{client._id}]"
            )
        # stop message handler thread before exiting
        self.terminate_thread(msg_handler_thread, msg_handler_q)
        time.sleep(0.2)
        self.logger.debug(
            f"Exiting handle client loop, "\
            f"Client ID = [{client._id}]"
        )
    
    def exchange_keys_with_client(self, transfer_agent: NetworkDataTransferer):
        self.logger.debug("Begining keys exchange with client.")
        self.lock.acquire()
        client_crypt = copy(self.crypt)
        transfer_agent.send(self.crypt.export_keys())
        time.sleep(0.1)
        client_crypt.import_keys(transfer_agent.receive())
        time.sleep(0.1)
        self.logger.debug(f"Sending hmac key: {self.msg_guardian.get_key()}")
        transfer_agent.send(
            client_crypt.encrypt(self.msg_guardian.get_key())
        )
        self.lock.release()
        self.logger.debug("Keys exchange finished.")
        return (client_crypt, self.msg_guardian)

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
        client_transfer_agent = self.transfer.__class__(
                                    client_socket, self.logger
                                )
        client_crypt, client_msg_guardian = self.exchange_keys_with_client(
                                                client_transfer_agent
                                            )
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
            new_id,
            address,
            client_setup_data["nickname"],
            client_setup_data["color"],
            client_transfer_agent,
            client_crypt,
            client_msg_guardian # for future usage
        )
        self.logger.debug(
            "New client registry successfully created, "\
            f"Client ID=[{new_client._id}]"
        )
        # add client to clients list
        self.clients.update({new_client._id: new_client})
        # create client's thread
        new_client_thread = Thread(
            target=self.handle_client,
            args=(new_client,),
            name=f"{new_client._id}_HANDLER"
        )
        # add client's thread to threads list
        self.client_threads.update({
            int(new_client_thread.name.split("_")[0]): new_client_thread
        })
        # start new client's thread
        self.logger.debug(f"Starting client [{new_client._id}] thread.")
        new_client.set_state(active=True)
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
                    f"Client ID=[{new_client._id}]"
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
        self.broadcast_enqueuer_thread = Thread(
            target=self.broadcast_enqueuer,
            args=(self, self.broadcast_q, self.logger),
            name="BROADCASTER"
            )
        self.broadcast_enqueuer_thread.start()
        self.logger.debug("Broadcaster thread started.")

        self.logger.debug("Starting replier thread.")
        self.reply_enqueuer_thread = Thread(
            target=self.reply_enqueuer,
            args=(self, self.reply_q, self.logger),
            name="REPLIER"
            )
        self.reply_enqueuer_thread.start()
        self.logger.debug("Replier thread started.")

        self.logger.debug("Starting dispatcher thread.")
        self.dispatch_thread = Thread(
            target=self.dispatch,
            args=(self, self.dispatch_q, self.logger),
            name="DISPATCHER"
            )
        self.dispatch_thread.start()
        self.logger.debug("Dispatcher thread started.")

        self.logger.debug("Starting connection handler thread.")
        self.connections_thread = Thread(
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
        self.msg_guardian.logger = self.logger
        self.q_listener.start()
        self.address = (SERVER_IP, SERVER_PORT)
        self.logger.info(f"Starting the server @{self.address} ...")
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
        client.set_state(active=False)
        time.sleep(0.1)
        self.logger.debug(f"Closing client socket. Client ID #[{client._id}]")
        client.transfer.close_socket()
        try:
            self.clients.pop(client._id)
        except KeyError as e:
            self.logger.debug(
                f"Client with ID [{client._id}] is not on the list. "\
                f"Description={e}"
            )
        self.logger.info(
            f"Client with ID #[{client._id}] disconnected."
        )
    
    def consume_queue(self, q: Queue, thread_name):
        try:
            while not q.empty:
                _ = q.get_nowait()
                self.logger.debug(f"Queue item: {_}")
                q.task_done()
        except Empty:
            pass
        self.logger.debug(f"{thread_name} queue consumed.")

    def terminate_thread(self, t: Thread, q: Queue = None):
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

    def terminate_client_thread(self, thread: Thread):
        attempts = 0
        while thread.is_alive() and attempts < 4:
            try:
                thread.join()
                self.logger.debug(f"Client thread [{thread.name}] joined.")
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
        self.logger.info("Sendind disconnect command to clients...")
        disconnect_cmd = Command(
            CommandType.DISCONNECT,
            (self._id, self.name)
        )
        self.broadcast_q.put(disconnect_cmd)
        time.sleep(0.2)
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
        self.logger.debug("Terminating QueueListener thread...")
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
        TCPIPv4DataTransferer(),
        RSAFernetCryptographer(),
        HMACMessageGuardian(DictBasedMessageFactory())
    )
    server.start()