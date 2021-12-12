from message import *
from constants import *
from transfer import NetworkDataTransferer, TCPIPv4DataTransferer
from cryptographer import Cryptographer, RSAFernetCryptographer
from logging import LogRecord, handlers
from workers import Worker
from queue import Queue, Empty
from threading import Thread, Lock
import logger


class Client(Thread):
    def __init__(self, nickname: str, color: str, server_address: tuple,
    data_transferer: NetworkDataTransferer, cryptographer: Cryptographer,
    msg_guardian: MessageGuardian
    ):
        super().__init__()
        self.nickname = nickname
        self.name = self.nickname.upper()
        self.color = color # hex nickname color
        self.server_address = server_address
        self.transfer = data_transferer
        self.crypt = cryptographer
        self.msg_guardian = msg_guardian

    ID: int() 
    address: tuple 
    running: bool
    logging_q = Queue()
    dispatch_q = Queue()
    chatbox_q = Queue()
    disconnect_q = Queue()
    message_output_q = Queue()
    lock = Lock()
    errors_count = 0
    connected = False

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

    @Worker
    def write_to_chatbox(self, message):
        if isinstance(message, Message):
            self.logger.debug(
                "Putting message into output queue. "\
                f"Message = {message}")
            if self.connected:
                self.message_output_q.put(message)
            print(
                f"****** [CHATBOX] [Message ID: {message._id}]",
                f"(Client ID: {message._from[0]}) {message._from[1]}:",
                f"{message._data} ******"
            )
        else:
            self.logger.debug(f"Not a message. Content=[{message}]")
        
    def prepare_msg_to_dispatch(self, msg):
        packed_msg = self.msg_guardian.pack(msg)
        return self.crypt.encrypt(packed_msg)

    @Worker
    def dispatch(self, message):
        if isinstance(message, Message):
            encrypted_message = None
            try:
                encrypted_message = self.prepare_msg_to_dispatch(message)
                self.transfer.send(encrypted_message)
                self.logger.debug(
                    f"{SuccessDescription._SUCCESSFULL_SEND} "\
                    f"Class=[{message.__class__.__name__}] "\
                    f"Type=[{message._code}] "\
                    f"Content: {message._data}"
                )
            except Exception as e:
                self.logger.error(ErrorDescription._FAILED_TO_SEND)
                args = (encrypted_message, message)
                self.handle_exceptions(e, *args)
            finally:
                time.sleep(CLT_SEND_SLEEP_TIME)

    def handle_broadcast_command(self, command: Command):
        reply = Reply(
            ReplyType.SUCCESS,
            (self.ID, self.nickname),
            ReplyDescription._SUCCESSFULL_RECV,
            _to=SERVER_ID,
            _message_id=command._id,
        )
        self.logger.debug(
            f"Received command "\
            f"from {command._from[1]}: "\
            f"Message ID [{command._id}]: "\
            f"{command}"
        )
        self.chatbox_q.put(command)
        self.dispatch_q.put(reply)
    
    def handle_query_command(self, command: Command):
        pass

    def handle_disconnect_command(self, command: Command):
        self.logger.info(f"Received disconnect command from the server.")
        self.disconnect_q.put(QueueSignal._shutdown)
        time.sleep(0.2)

    def handle_success_reply(self, reply: Reply):
        # success and error behave the same for now
        self.logger.debug(
                f"Received reply "\
                f"from {reply._from[1]}: "\
                f"Message ID [{reply._id}] "\
                f"{reply}"
        )

    def handle_error_reply(self, reply: Reply):
        # success and error behave the same for now
        self.logger.info(
                f"Received reply "\
                f"from {reply._from[1]}: "\
                f"Message ID [{reply._id}] "\
                f"{reply}"
        )
    
    def handle_unknown_message_type(self, e: Exception, *args):
        self.logger.error(ErrorDescription._FAILED_RECV)
        self.logger.debug(
            f"{e.__class__.__name__}: "\
            f"{ErrorDescription._UNKNOWN_MSG_TYPE} "\
            f"Messagetype = {e.args[1]}"
        )
        reply = Reply(
                    ReplyType.ERROR,
                    (self.ID, self.nickname),
                    ReplyDescription._UNKNOWN_MSG_TYPE,
                    _to=SERVER_ID,
                )
        self.dispatch_q.put(reply)
    
    def handle_integrity_fail(self, e: Exception, *args):
        self.logger.error(ErrorDescription._FAILED_RECV)
        self.logger.debug(ErrorDescription._INTEGRITY_FAILURE)
        reply = Reply(
                    ReplyType.ERROR,
                    (self.ID, self.nickname),
                    ReplyDescription._INTEGRITY_FAILURE,
                    _to=SERVER_ID,
                )
        self.dispatch_q.put(reply)

    def handle_encryption_error(self, e: Exception, *args):
        self.logger.error(ErrorDescription._MSG_DECRYPT_ERROR)
        self.logger.debug(e)
        self.errors_count += 1
        if self.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
            self.logger.debug("Too many encryption errors")
            self.disconnect_q.put(QueueSignal._disconnect)

    def handle_invalid_message_code(self, e: Exception, *args):
        self.logger.error(
            f"{ErrorDescription._INVALID_MSG_CODE} "\
            f"Message code = {args[1]._code} "
        )

    def handle_send_error(self, e: Exception, *args):
        self.logger.debug(
            f"{ErrorDescription._FAILED_TO_SEND} "\
            f"Message ID = [{args[1]._id}] "
        )
        self.errors_count += 1
        if self.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
            self.logger.critical(
                ErrorDescription._LOST_CONNECTION_W_SRV
            )
            self.logger.debug(f"Errors count = {self.errors_count}")
            self.disconnect_q.put(QueueSignal._disconnect)
            time.sleep(0.05)


    def handle_receive_error(self, e: Exception, *args):
        if self.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
            if self.running:
                self.logger.critical(
                    ErrorDescription._LOST_CONNECTION_W_SRV
                )
                self.logger.debug(f"Errors count = {self.errors_count}")
                self.disconnect_q.put(QueueSignal._disconnect)
            time.sleep(0.05)
        elif self.running:
            self.logger.error(ErrorDescription._FAILED_RECV)
            self.logger.debug(e)
            reply = Reply(
                        ReplyType.ERROR,
                        (self.ID, self.nickname),
                        ErrorDescription._FAILED_RECV,
                        _to=SERVER_ID,
                    )
            self.dispatch_q.put(reply)
        self.errors_count += 1

    def handle_critical_error(self, e: Exception, *args):
        self.logger.debug(e)
        self.errors_count += 1
        if self.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
            if self.running:
                self.logger.critical(
                    ErrorDescription._LOST_CONNECTION_W_SRV
                )
                self.logger.debug(f"Errors count = {self.errors_count}")
                self.disconnect_q.put(QueueSignal._disconnect)
            time.sleep(0.05)

    def handle_connect_error(self, e: Exception, *args):
        ip, port = args
        self.logger.error(
            f"{ErrorDescription._UNABLE_TO_CONCT_W_SRV} "\
            f"Entered address: ({ip}:{port})"
        )
        self.logger.debug(f"Description: {e}")

    def handle_no_error_handler(self, e: Exception, *args):
        self.logger.debug("".join((
            ErrorDescription._ERROR_NO_HANDLER_DEFINED,
            f" Error class: {e.__class__.__name__}",
        )))
        self.logger.exception(e)
        self.errors_count += 1
        if self.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
            self.logger.critical(
                ErrorDescription._TOO_MANY_ERRORS
            )
            self.disconnect_q.put(QueueSignal._disconnect)
            time.sleep(0.05)

    incoming_msg_handlers = {
        CommandType.BROADCAST : handle_broadcast_command,
        CommandType.QUERY : handle_query_command,
        CommandType.DISCONNECT : handle_disconnect_command,
        ReplyType.SUCCESS : handle_success_reply,
        ReplyType.ERROR : handle_error_reply
    }

    error_handlers = {
        UnknownMessageType.__name__ : handle_unknown_message_type,
        InvalidDataForEncryption.__name__ : handle_encryption_error,
        EncryptionError.__name__ : handle_encryption_error,
        TypeError.__name__ : handle_encryption_error,
        IntegrityCheckFailed.__name__ : handle_integrity_fail,
        KeyError.__name__ : handle_invalid_message_code,
        SendError.__name__ : handle_send_error,
        ReceiveError.__name__ : handle_receive_error,
        CriticalTransferError.__name__ : handle_critical_error,
        ConnectionRefusedError.__name__ : handle_connect_error,
        TimeoutError.__name__ : handle_connect_error,
        OverflowError.__name__ : handle_connect_error,
        socket.gaierror.__name__ : handle_connect_error,
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

    @Worker
    def handle_incoming_message(self, buffer):
        message = None
        try:
            decrypted_message = self.crypt.decrypt(buffer)
            message = self.msg_guardian.unpack(decrypted_message)
            self.incoming_msg_handlers[message._code](self, message)
        except Exception as e:
            self.logger.error(ErrorDescription._FAILED_TO_HANDLE_MSG)
            args = (buffer, message)
            self.handle_exceptions(e, *args)

    def handle_receive(self):
        msg_handler_q = Queue()
        message_handler_thread = Thread(
            target=self.handle_incoming_message,
            args=(self, msg_handler_q, self.logger),
            name=f"{self.ID}_MSGHNDLR",
            daemon=True
        )
        message_handler_thread.start()
        while self.running:
            buffer = None
            try:
                buffer = self.transfer.receive()
                msg_handler_q.put(buffer)
                self.logger.debug("Message put into handler queue.")
            except Exception as e:
                self.logger.debug(ErrorDescription._FAILED_RECV)
                args = (buffer,)
                self.handle_exceptions(e, *args)
        if not self.running:
            self.logger.debug(
                f"Running flag changed: set -> clear."
            )
        self.terminate_thread(message_handler_thread, msg_handler_q)
        self.logger.debug("Exiting persistence loop.")
    
    def handle_input(self, data: str):
        # this is for development purposes
        if data == "c:shut":
            message = Command(
                        CommandType.SHUTDOWN,
                        (self.ID, self.nickname)
                    )
            self.dispatch_q.put(message)
            time.sleep(0.5)
        elif data == "c:disc":
            self.disconnect_q.put(QueueSignal._disconnect)
        else:
            message = Command(
                        CommandType.BROADCAST,
                        (self.ID, self.nickname),
                        data.strip(),
                        _nick_color=self.color
                    )
            self.logger.debug("Enqueued message to dispatch.")
            self.dispatch_q.put(message)

    def is_connected(self):
        return self.connected

    def handle_connect(self, server_ip, server_port):
        self.logger.info("Connecting with the server...")
        self.logger.debug(f"Server address = [{server_ip}:{server_port}].")
        try:
            self.transfer._socket.connect((server_ip, server_port))
            self.logger.info("Connection with the server stabilished.")
            self.connected = True
            return True
        except Exception as e:
            self.handle_exceptions(e, server_ip, server_port)
            return False

    def consume_queue(self, q: Queue, thread_name):
        try:
            while not q.empty:
                _ = q.get()
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
        
    def handle_disconnect(self, make_request=True):
        self.logger.info("Disconnecting...")
        self.running = False
        self.logger.debug("Running flag changed: set -> clear.")
        # send disconnect command to server if desirable
        if make_request:
            self.logger.debug("Sending disconnect command to server.")
            disconnect_cmd = Command(
                        CommandType.DISCONNECT,
                        (self.ID, self.nickname),
                    )
            self.dispatch_q.put(disconnect_cmd)
        # terminate dispatcher thread
        self.terminate_thread(self.dispatch_thread, self.dispatch_q)
        time.sleep(0.5)
        # close socket
        self.transfer.close_socket()
        # terminate receiver thread
        self.terminate_thread(self.receive_thread)
        # terminate chatbox writer thread
        self.terminate_thread(self.chatbox_thread, self.chatbox_q)
        self.disconnect_q.put(QueueSignal._disconnect)
        self.logger.debug("Disconnect process finished.")
        self.connected = False
    
    def exchange_keys_with_server(self):
        self.logger.debug("Begining keys exchange with server.")
        self.lock.acquire()
        self.crypt.import_keys(self.transfer.receive())
        time.sleep(0.1)
        self.transfer.send(self.crypt.export_keys())
        time.sleep(0.1)
        self.msg_guardian.set_key(
            self.crypt.decrypt(self.transfer.receive())
        )
        self.logger.debug(f"Received hmac key: {self.msg_guardian.get_key()}")
        self.lock.release()
        self.logger.debug("Keys exchange finished.")

    def exchange_setup_data_with_server(self):
        # send encrypted client data 
        self.lock.acquire()
        self.logger.debug("Sending setup data to server.")
        setup_data =  json.dumps({
                            "nickname": self.nickname,
                            "color": self.color
                        })
        self.transfer.send(
            self.crypt.encrypt(
                setup_data.encode()
            )
        )
        self.logger.debug("Setup data successfully sent.")

        # receive ID generated by the server
        self.logger.debug("Waiting for my ID.")
        self.ID =   struct.unpack("<I",
                        self.crypt.decrypt(
                            self.transfer.receive()
                        )
                    )[0]
        self.lock.release()
        self.logger.debug(f"My ID: {self.ID}")
        self.logger.debug("Setup data exchange completed.")

    def setup_worker_threads(self):
        self.logger.debug("Starting chatbox writer thread.")
        self.chatbox_thread = Thread(
            target=self.write_to_chatbox,
            args=(self, self.chatbox_q, self.logger),
            name="CHATBOX_WRITER"
            )
        self.chatbox_thread.start()
        self.logger.debug("Chatbox writer thread started.")

        self.logger.debug("Starting dispatcher thread.")
        self.dispatch_thread = Thread(
            target=self.dispatch,
            args=(self, self.dispatch_q, self.logger),
            name="DISPATCHER"
            )
        self.dispatch_thread.start()
        self.logger.debug("Dispatcher thread started.")

        self.logger.debug("Starting receiver thread.")
        self.receive_thread = Thread(
            target=self.handle_receive,
            name="RECEIVER"
            )
        self.receive_thread.start()
        self.logger.debug("Receiver thread started.")

    def run(self):
        self.setup_logger()
        self.transfer.logger = self.logger
        self.crypt.logger = self.logger
        self.msg_guardian.logger = self.logger
        self.q_listener.start()
        self.running = True
        connection_success = self.handle_connect(
            self.server_address[0],
            self.server_address[1]
        )
        if not connection_success:
            self.logger.info("Exiting...")
            self.running = False
            self.q_listener.stop()
            time.sleep(0.2)
            return
        self.exchange_keys_with_server()
        self.exchange_setup_data_with_server()
        self.setup_worker_threads()
        # wait for disconnect signal
        while self.running:
            signal = self.disconnect_q.get()
            if signal is QueueSignal._shutdown:
                self.logger.info("Server is shutting down.")
                make_request = False
            else:
                self.logger.debug("Got a disconnect signal.")
                make_request = True 
            self.handle_disconnect(make_request)
            self.logger.info("Disconnected.")
            time.sleep(0.1)
            self.q_listener.stop()
            self.disconnect_q.task_done()


#for test purposes
if __name__ == "__main__":
    client = Client(
        input("Insert nickname: "),
        "blue",
        (SERVER_IP, SERVER_PORT),
        TCPIPv4DataTransferer(),
        RSAFernetCryptographer(),
        HMACMessageGuardian(DictBasedMessageFactory())
    )
    client.start()
    time.sleep(1)

    while client.running:
        client.logger.debug("Waiting for input.")
        msg = input("> ")
        client.handle_input(msg.rstrip())
        time.sleep(0.3)
    