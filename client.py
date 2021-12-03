from message import *
from constants import *
from network_agent import NetworkAgent
from cryptographer import Cryptographer


class Client(NetworkAgent):
    def __init__(self, nickname: str, color: str, server_address: tuple):
        super().__init__()
        self.nickname = nickname # client's nickname
        self.name = self.nickname.upper()
        self.color = color # hex nickname color
        self.server_address = server_address

    dispatch_q = queue.Queue()
    chatbox_q = queue.Queue()
    disconnect_q = queue.Queue()
    message_output_q = queue.Queue()
    ID = int() # determined by the server later
    server_public_key = tuple() # obtained later
    errors_count = 0
    connected = False

    def write_to_chatbox(self):
        active_thread = threading.Event()
        active_thread.set()
        while active_thread.is_set() and self.running.is_set():
            message = self.chatbox_q.get()
            if isinstance(message, Message):
                self.logger.info(
                    "Putting message into output queue. "\
                    f"Message = {message}")
                self.message_output_q.put(message)
                print(
                    f"****** [CHATBOX] [Message ID: {message._id}]",
                    f"(Client ID: {message._from[0]}) {message._from[1]}:",
                    f"{message._data} ******"
                )
            elif message is QueueSignal._terminate_thread:
                self.logger.debug("Terminate thread signal received.")
                active_thread.clear()
            else:
                self.logger.debug(f"Not a message. Content=[{message}]")
            self.chatbox_q.task_done()
        self.logger.debug("Exiting chatbox_writer thread persistence loop.")
        
    def dispatch(self):
        os_errors_count = 0
        active_thread = threading.Event()
        active_thread.set()
        while active_thread.is_set() and self.running.is_set():
            message = self.dispatch_q.get()
            self.logger.debug("Got an item.")
            if isinstance(message, Message):
                try:
                    packed_message = self.msg_guardian.pack(message)
                    encrypted_message = self.crypt.encrypt(packed_message)
                    if self.can_send_to(self.socket):
                        self.send(self.socket, encrypted_message)
                        self.logger.debug(
                            f"{SuccessDescription._SUCCESSFULL_SEND} "\
                            f"Class=[{message.__class__.__name__}] "\
                            f"Type=[{message._code}] "\
                            f"Content: {message._data}"
                        )
                except (NullData, NonBytesData, SendError) as e:
                        self.logger.debug(
                            f"{ErrorDescription._FAILED_TO_SEND} "\
                            f"Message ID = [{message._id}]"
                        )
                except (InvalidDataForEncryption, InvalidRSAKey) as e:
                    self.logger.error("Could not send message.")
                    self.logger.debug(e)
                except CriticalTransferError as e:
                    self.logger.error(ErrorDescription._FAILED_TO_SEND)
                    self.logger.debug(e)
                    os_errors_count += 1
                    if os_errors_count > CRITICAL_ERRORS_MAX_NUMBER:
                        self.logger.critical(
                            ErrorDescription._LOST_CONNECTION_W_SRV
                            )
                        self.disconnect_q.put(QueueSignal._disconnect)
                        time.sleep(0.05)
                finally:
                    time.sleep(CLT_SEND_SLEEP_TIME)
            elif message is QueueSignal._terminate_thread:
                self.logger.debug("Terminate thread signal received.")
                active_thread.clear()
            else:
                self.logger.debug(
                    f"{ErrorDescription._UNKNOWN_MSG_TYPE} "\
                    f"Message = {message} "\
                    f"type = {type(message)}"
                    )
            self.dispatch_q.task_done()
        self.logger.debug("Exiting dispatch thread persistence loop.")

    def handle_broadcast_command(self, command: Command):
        reply = Reply(
            ReplyType.SUCCESS,
            (self.ID, self.nickname),
            SERVER_ID,
            command._id,
            ReplyDescription._SUCCESSFULL_RECV
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
        self.logger.info(f"Received {command._code} from the server")
        self.disconnect_q.put(QueueSignal._disconnect)

    def handle_success_reply(self, reply: Reply):
        self.logger.info(
                f"Received reply "\
                f"from {reply._from[1]}: "\
                f"Message ID [{reply._id}] "\
                f"{reply}"
        )

    def handle_error_reply(self, reply: Reply):
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
                    ErrorType.UNPACK_ERROR,
                    (self.ID, self.nickname),
                    client.ID,
                    None, 
                    ReplyDescription._UNKNOWN_MSG_TYPE
                )
        self.dispatch_q.put(reply)
    
    def handle_integrity_fail(self, e: Exception, *args):
        self.logger.error(ErrorDescription._FAILED_RECV)
        self.logger.debug(ErrorDescription._INTEGRITY_FAILURE)
        reply = Reply(
                    ErrorType.UNPACK_ERROR,
                    (self.ID, self.nickname),
                    client.ID,
                    None,
                    ReplyDescription._INTEGRITY_FAILURE
                )
        self.dispatch_q.put(reply)

    def handle_encryption_error(self, e: Exception, *args):
        self.logger.error(ErrorDescription._FAILED_RECV)
        self.logger.debug(e)
        self.errors_count += 1
        if self.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
            self.logger.debug("Too many encryption errors")
            self.disconnect_q.put(QueueSignal._disconnect)

    def handle_invalid_message_code(self, e: Exception, *args):
        self.logger.error(
            ErrorDescription._INVALID_MSG_CODE
            + f"Message code = {args[1]._code} "\
        )
    
    def handle_receive_error(self, e: Exception, *args):
        if self.running.is_set():
            self.logger.error(ErrorDescription._FAILED_RECV)
            self.logger.debug(e)
            reply = Reply(
                ReplyType.ERROR,
                (self.ID, self.nickname),
                SERVER_ID,
                None,
                ErrorDescription._FAILED_RECV
            )
            self.dispatch_q.put(reply)

    def handle_critical_error(self, e: Exception, *args):
        if self.running.is_set():
            self.logger.error(ErrorDescription._FAILED_RECV)
            self.logger.debug(e)
        self.errors_count += 1
        if self.errors_count > CRITICAL_ERRORS_MAX_NUMBER:
            self.logger.critical(
                ErrorDescription._LOST_CONNECTION_W_SRV
            )
            self.disconnect_q.put(QueueSignal._disconnect)
            time.sleep(0.05)

    message_handlers = {
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
        ReceiveError.__name__ : handle_receive_error,
        CriticalTransferError.__name__ : handle_critical_error
    }

    def handle_incoming_message(self, q: queue.Queue):
        active = threading.Event()
        active.set()
        while active.is_set():
            item = q.get()
            if isinstance(item, bytes):
                decrypted_message = None 
                message = None
                try:
                    decrypted_message = self.crypt.decrypt(item)
                    message = self.msg_guardian.unpack(decrypted_message)
                    self.message_handlers[message._code](self, message)
                except Exception as e:
                    try:
                        err = e.__class__.__name__
                        self.logger.error(f"{err} exception raised. Sending to handler.")
                        args = (decrypted_message, message)
                        self.error_handlers[err](self, e, *args)
                    except KeyError:
                        self.logger.error("".join((
                            ErrorDescription._ERROR_NO_HANDLER_DEFINED,
                            f" Error class: {err}",
                            f" Error description: {e}"
                        )))
            elif item is QueueSignal._terminate_thread:
                self.logger.debug("Got terminate signal from the queue.")
                active.clear()
            q.task_done()
        self.logger.debug("Exiting persistence loop.")

    def handle_receive(self):
        msg_handler_q = queue.Queue()
        message_handler_thread = threading.Thread(
            target=self.handle_incoming_message,
            args=[msg_handler_q],
            name=f"{self.ID}_MSGHNDLR",
            daemon=True
        )
        message_handler_thread.start()
        while self.running.is_set():
            buffer = None
            try:
                buffer = self.receive(self.socket)
                self.logger.debug("Message received.")
                msg_handler_q.put(buffer)
                self.logger.debug("Message put into handler queue.")
            except Exception as e:
                try:
                    err = e.__class__.__name__
                    self.logger.error(f"{err} exception raised. Sending to handler.")
                    args = (buffer,)
                    self.error_handlers[err](self, e, *args)
                except KeyError:
                    self.logger.error("".join((
                        ErrorDescription._ERROR_NO_HANDLER_DEFINED,
                        f" Error class: {err}",
                        f" Error description: {e}"
                    )))
            finally:
                time.sleep(CLT_RECV_SLEEP_TIME)
        if not self.running.is_set():
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
                        (self.ID, self.nickname),
                        data,
                    )
            self.dispatch_q.put(message)
            time.sleep(0.5)
            self.disconnect_q.put(QueueSignal._disconnect)
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
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.address = self.socket.connect((server_ip, server_port))
            self.logger.info("Connection with the server stabilished.")
            self.connected = True
            return True
        except (ConnectionRefusedError, TimeoutError) as e:
            self.logger.info("Could not stabilish connection with the server.")
            self.logger.debug(f"Description: {e}")
            return False
        except OverflowError as e:
            self.logger.info("Invalid port.")
            self.logger.debug(f"Description: {e}")
            return False
        except socket.gaierror as e:
            self.logger.info("Invalid IP.")
            self.logger.debug(f"Description: {e}")
            return False
        
    def handle_disconnect(self):
        self.logger.info("Disconnecting...")
        self.running.clear()
        self.logger.debug("Running flag changed: set -> clear.")
        # send disconnect command to server
        self.logger.debug("Sending disconnect command to server.")
        disconnect_cmd = Command(
                    CommandType.DISCONNECT,
                    (self.ID, self.nickname),
                )
        self.dispatch_q.put(disconnect_cmd)
        try:
            self.dispatch_thread.join()
            self.logger.debug("Dispatcher thread terminated.")
        except RuntimeError:
            # The running flag is cleared at this point,
            # so, after dispatching the disconnect command above,
            # the dispatcher thread will hopefully terminate.
            # But in case it does not terminate,
            # run the following procedure.
            self.logger.debug(
                "Dispatcher thread did not terminate as expected."
            )
            self.terminate_thread(self.dispatch_thread, self.dispatch_q)
        # close socket
        time.sleep(0.5)
        self.close_socket(self.socket)
        # terminate receiver thread
        self.terminate_thread(self.receive_thread)
        # terminate chatbox writer thread
        self.terminate_thread(self.chatbox_thread, self.chatbox_q)

        self.logger.debug("Disconnect process finished.")
        self.connected = False
    
    def exchange_keys_with_server(self):
        self.logger.debug(
            "Starting encryption keys exchange with server."
        )
        self.logger.debug(f"My RSA public key: {self.public_key}")

        # receive temporary fernet key 
        encapsulated_key = self.receive(self.socket)
        temp_key = encapsulated_key[
            DUMMY_ENCODED_SIZE:DUMMY_ENCODED_SIZE+FERNET_KEY_SIZE
        ]
        self.logger.debug(
            "Received temporary fernet key. "\
            f"Key = [{temp_key}]"
        )
        time.sleep(0.1)

        # receive server public key
        self.logger.debug("Waiting for server's RSA public key.")
        temp_fernet = Fernet(temp_key)
        key = base64.urlsafe_b64decode(
            temp_fernet.decrypt(
                self.receive(self.socket)
            )
        ).decode().split("-")
        server_public_key = (int(key[0]), int(key[1]))
        time.sleep(0.1)
        self.logger.debug(f"Server public key: {server_public_key}")

        # send public key to server
        self.logger.debug("Sending RSA public key to server.")
        enc_rsa_key = temp_fernet.encrypt(
            base64.urlsafe_b64encode(
                f"{self.public_key[0]}-{self.public_key[1]}".encode()
            )
        )
        self.send(self.socket, enc_rsa_key)
        time.sleep(0.1)
        self.logger.debug("RSA public key sent.")

        # create temporary crypt object
        temp_crypt = Cryptographer(
            self.private_key,
            server_public_key,
            temp_key,
            self.logger
        )

        # receive encrypted fernet key
        self.logger.debug("Waiting for fernet key.")
        fernet_key = temp_crypt.decrypt(self.receive(self.socket))
        self.logger.debug(f"Fernet key: {fernet_key}")
        time.sleep(0.1)

        # receive encrypted hmac key
        self.logger.debug("Waiting for HMAC key.")
        self.hmac_key = temp_crypt.decrypt(self.receive(self.socket))
        self.logger.debug(f"HMAC key: {self.hmac_key}")
        #create message guardian for pack/unpack
        self.msg_guardian = MessageGuardian(self.hmac_key)
        time.sleep(0.1)

        # create cryptographer object
        self.crypt = Cryptographer(
            self.private_key,
            server_public_key,
            fernet_key,
            self.logger 
        )

        self.logger.debug("Keys exchange terminated.")
    
    def exchange_setup_data_with_server(self):
        # send encrypted client data 
        self.logger.debug("Sending setup data to server.")
        setup_data =  json.dumps({
                            "nickname": self.nickname,
                            "color": self.color
                        })
        self.send(
            self.socket,
            self.crypt.encrypt(
                setup_data.encode()
            )
        )
        self.logger.debug("Setup data successfully sent.")

        # receive ID generated by the server
        self.logger.debug("Waiting for my ID.")
        self.ID =   struct.unpack("<I",
                        self.crypt.decrypt(
                            self.receive(self.socket)
                        )
                    )[0]
        self.logger.debug(f"My ID: {self.ID}")
        self.logger.debug("Setup data exchange completed.")

    def setup_worker_threads(self):
        self.logger.debug("Starting chatbox writer thread.")
        self.chatbox_thread = threading.Thread(
            target=self.write_to_chatbox,
            name="CHATBOX_WRITER"
            )
        self.chatbox_thread.start()
        self.logger.debug("Chatbox writer thread started.")

        self.logger.debug("Starting dispatcher thread.")
        self.dispatch_thread = threading.Thread(
            target=self.dispatch,
            name="DISPATCHER"
            )
        self.dispatch_thread.start()
        self.logger.debug("Dispatcher thread started.")

        self.logger.debug("Starting receiver thread.")
        self.receive_thread = threading.Thread(
            target=self.handle_receive,
            name="RECEIVER"
            )
        self.receive_thread.start()
        self.logger.debug("Receiver thread started.")

    def run(self):
        self.setup_logger()
        self.running.set()
        self.q_listener.start()
        connection_success = self.handle_connect(
            self.server_address[0],
            self.server_address[1]
        )
        if not connection_success:
            self.logger.info("Exiting...")
            self.running.clear()
            self.q_listener.stop()
            time.sleep(0.2)
            return
        self.exchange_keys_with_server()
        self.exchange_setup_data_with_server()
        self.setup_worker_threads()
        # wait for disconnect signal
        while self.running.is_set():
            signal = self.disconnect_q.get()
            if signal is QueueSignal._disconnect:
                self.logger.debug("Got a disconnect signal.")
                self.handle_disconnect()
                self.logger.info("Disconnected.")
                time.sleep(0.1)
                self.q_listener.stop()
            else:
                self.logger.debug("Got a invalid disconnect signal.")


#for test purposes
if __name__ == "__main__":
    client = Client(
        input("Insert nickname: "),
        "blue",
        (SERVER_IP, SERVER_PORT)
    )
    client.start()
    time.sleep(1)

    while client.running.is_set():
        client.logger.debug("Waiting for input.")
        msg = input("> ")
        client.handle_input(msg.rstrip())
        time.sleep(0.3)
    