from message import *
from constants import *
from network_agent import NetworkAgent


class Client(NetworkAgent):
    def __init__(self, nickname: str, color: str):
        super().__init__()
        self.nickname = nickname # client's nickname
        self.name = self.nickname # for test purposes
        self.color = color # hex nickname color
        self.dispatch_q = queue.Queue()
        self.chatbox_q = queue.Queue()
        self.disconnect_q = queue.Queue()
        self.ID = int() # determined by the server later
        self.server_public_key = tuple() # obtained later

    def write_to_chatbox(self):
        while self.running.is_set():
            message = self.chatbox_q.get()
            if isinstance(message, Message):
                #for now just print
                print(
                    f"****** [CHATBOX] [Message ID: {message._id}]",
                    f"(CLient ID: {message._from[0]}) {message._from[1]}:",
                    f"{message._data} ******"
                )
            else:
                self.logger.debug(f"Not a message. Content=[{message}]")
            self.chatbox_q.task_done()

    def dispatch(self):
        os_errors_count = 0
        while self.running.is_set():
            message = self.dispatch_q.get()
            if isinstance(message, Message):
                try:
                    packed_message = message.pack(self.hmac_key)
                    encrypted_message = self.encrypt(
                        packed_message,
                        self.server_public_key
                        )

                    self.send(self.socket, encrypted_message)

                    self.logger.debug(" ".join([
                        SuccessDescription._SUCCESSFULL_SEND,
                        f"Class=[{message.__class__.__name__}] ",
                        f"Type=[{message._code}] ",
                        f"Content: {message._data}"
                    ]))
                except (NullData, NonBytesData, SendError) as e:
                        self.logger.debug(" ".join([
                            ErrorDescription._FAILED_TO_SEND,
                            f"Message ID = [{message._id}]"
                        ]))
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
                        self.disconnect_q.put(1)
                        time.sleep(0.05)
                    continue

                finally:
                    time.sleep(CLT_SEND_SLEEP_TIME)
            self.dispatch_q.task_done()

    def handle_receive(self):
        os_errors_count = 0
        while self.running.is_set():

            # receive data
            try:
                buffer = self.receive_buffer(self.socket)
            
            except ReceiveError as e:
                self.logger.error(ErrorDescription._FAILED_RECV)
                self.logger.debug(e)
                reply = Reply(
                    ReplyType.ERROR,
                    (self.ID, self.nickname),
                    SERVER_ID,
                    "Unknown",
                    ErrorDescription._FAILED_RECV
                )
                self.dispatch_q.put(reply)
                continue

            except CriticalTransferError as e:
                self.logger.error(ErrorDescription._FAILED_RECV)
                self.logger.debug(e)
                os_errors_count += 1
                if os_errors_count > CRITICAL_ERRORS_MAX_NUMBER:
                    self.logger.critical("Lost connection with the server.")
                    self.disconnect_q.put(1)
                    time.sleep(0.05)
                continue

            try:
                decrypted_message = self.decrypt(
                    buffer,
                    self.private_key
                )
                message = Message.unpack(decrypted_message, self.hmac_key)

                if isinstance(message, Command):
                    if message._code == CommandType.BROADCAST:
                        reply = Reply(
                            ReplyType.SUCCESS,
                            (self.ID, self.nickname),
                            SERVER_ID,
                            message._id,
                            ReplyDescription._SUCCESSFULL_RECV
                        )
                        self.logger.debug(
                            f"Received {message._type.upper()} "\
                            f"from {message._from[1]}: "\
                            f"Message ID [{message._id}]: "\
                            f"{message}"
                        )
                        self.chatbox_q.put(message)
                        self.dispatch_q.put(reply)
                elif isinstance(message, Reply):
                    self.logger.debug(
                            f"Received {message._type.upper()} "\
                            f"from {message._from[1]}: "\
                            f"Message ID [{message._id}] "\
                            f"{message}"
                    )
            # it's an error generated by the unpack function
            except IntegrityCheckFailed:
                self.logger.error(
                            "Message "\
                            f"{ReplyDescription._FAILED_RECV}"
                        )
                self.logger.debug("Integrity check failed.")
                reply = Reply(
                            ErrorType.UNPACK_ERROR,
                            (self.ID, self.nickname),
                            client.ID,
                            "-",
                            ReplyDescription._INTEGRITY_FAILURE
                        )
                self.dispatch_q.put(reply)
            except UnknownMessageType:
                self.logger.error(
                            "Message "\
                            f"{ReplyDescription._FAILED_RECV}"
                        )
                self.logger.debug(ReplyDescription._UNKNOWN_MSG_TYPE)
                reply = Reply(
                            ErrorType.UNPACK_ERROR,
                            (self.ID, self.nickname),
                            client.ID,
                            "-",
                            ReplyDescription._UNKNOWN_MSG_TYPE
                        )
                self.dispatch_q.put(reply)
            except (InvalidDataForEncryption, InvalidRSAKey) as e:
                self.logger.info("Could not receive message.")
                self.logger.debug(e)
            except TypeError:
                pass
            finally:
                time.sleep(CLT_RECV_SLEEP_TIME)
    
    def handle_input(self, data: str):
        if data == "c:shut":
            message = Command(
                        CommandType.SHUTDOWN,
                        (self.ID, self.nickname),
                        data,
                    )
            self.dispatch_q.put(message)
            time.sleep(1)
            self.disconnect_q.put(1)
        elif data == "c:disc":
            self.disconnect_q.put(1)
        else:
            message = Command(
                        CommandType.BROADCAST,
                        (self.ID, self.nickname),
                        data,
                    )
            self.dispatch_q.put(message)

    def handle_connect(self, server_ip, server_port):
        self.logger.info("Connecting with the server.")
        self.logger.debug(f"Server address = [{server_ip}:{server_port}].")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.address = self.socket.connect((server_ip, server_port))
            self.logger.info("Connection with the server stabilished.")
            return True
        except (ConnectionRefusedError, TimeoutError) as e:
            self.logger.info("Could not stabilish connection with the server.")
            self.logger.debug(f"Description: {e}")
            return False
        
    def handle_disconnect(self):
        self.logger.info("Disconnecting...")
        self.running.clear()
        self.logger.debug("Running flag changed: set -> clear.")

        # send disconnect command to server
        disconnect_cmd = Command(
                    CommandType.DISCONNECT,
                    (self.ID, self.nickname),
                )
        self.dispatch_q.put(disconnect_cmd)
        try:
            self.dispatch_thread.join()
            self.logger.debug("Dispatch thread terminated.")
        except RuntimeError:
            # The running flag is cleared at this point,
            # so, after dispatching the disconnect command above,
            # the dispatcher thread will hopefully terminate.
            # But in case it does not terminate,
            # run the following procedure.
            self.logger.debug(
                "Dispatcher thread did not terminate as expected."
            )
            self.dispatch_q.put(1)
            self.logger.debug("Sent terminate command to dispatcher thread.")
            self.logger.debug("Waiting for dispatch queue to join.")
            self.dispatch_q.join()
            self.logger.debug("Dispatch queue joined.")
            self.logger.debug("Waiting for dispatch thread to terminate.")
            try:
                self.dispatch_thread.join()
                self.logger.debug("Dispatch thread terminated.")
            except RuntimeError:
                self.logger.error("Could not terminate dispatcher thread.")
                self.logger.debug(f"Threads: {threading.enumerate()}")

        # close socket
        time.sleep(0.5)
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.socket.close()
            self.logger.debug("Socket closed.")
        except OSError as e:
            self.logger.debug("Socket already closed.")
            self.logger.debug(f"Error description: {e}")
        
        # terminate receiver thread
        if self.receive_thread.is_alive():
            self.logger.debug("Waiting for receiver thread to terminate.")
            try:
                self.receive_thread.join()
                self.logger.debug("Receiver thread terminated.")
            except RuntimeError:
                self.logger.debug("Could not terminate receiver thread.")
                self.logger.debug(f"Threads: {threading.enumerate()}")
        else:
            self.logger.debug("Receiver thread terminated.")

        # terminate chatbox writer thread
        if self.chatbox_thread.is_alive():
            self.chatbox_q.put(1)
            self.logger.debug("Sent terminate command to chatbox thread.")
            self.logger.debug("Waiting for chatbox queue to join.")
            self.chatbox_q.join()
            self.logger.debug("Chatbox queue joined.")
            self.logger.debug("Waiting for chatbox thread to terminate.")
            try:
                self.chatbox_thread.join()
                self.logger.debug("Chatbox thread terminated.")
            except RuntimeError:
                self.logger.error("Could not terminate chatbox thread.")
        self.logger.debug("Disconnect process finished.")
    
    def run(self):
        self.setup_logger()
        self.running.set()
        connection_success = self.handle_connect(SERVER_IP, SERVER_PORT)

        if not connection_success:
            self.q_listener.start()
            self.logger.info("Exiting...")
            self.running.clear()
            self.q_listener.stop()
            time.sleep(0.2)
            return

        self.logger.debug(f"My public key: {self.public_key}")

        # receive server public key
        buffer = self.receive(self.socket).decode().split("-")
        self.server_public_key = (int(buffer[0]), int(buffer[1]))
        self.logger.debug(f"Server public key: {self.server_public_key}")
        
        # send public key to server
        self.send(
            self.socket,
            f"{self.public_key[0]}-{self.public_key[1]}".encode()
        )

        # receive encrypted fernet and HMAC keys
        self.fernet_key = self.rsa_decrypt_b(
                            self.receive(self.socket),
                            self.private_key
                        )
        self.logger.debug(f"Fernet key: {self.fernet_key}")
        self.hmac_key = self.rsa_decrypt_b(
                            self.receive(self.socket),
                            self.private_key
                        )
        self.logger.debug(f"HMAC key: {self.hmac_key}")

        # send ecrypted client data 
        initial_data =  json.dumps({
                            "nickname": self.nickname,
                            "color": self.color
                        })
        self.send(
            self.socket,
            self.rsa_encrypt_b(
                initial_data.encode(),
                self.server_public_key
            )
        )

        # receive ID generated by the server
        self.ID =   struct.unpack("<I",
                        self.decrypt(
                            self.receive(self.socket),
                            self.private_key
                        )
                    )[0]
        Message.CLIENT_ID = self.ID
        self.logger.debug(f"My ID: {self.ID}")

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

        self.q_listener.start()

        # wait for disconnect signal
        disconnect_signal = self.disconnect_q.get()
        if disconnect_signal:self.handle_disconnect()
        self.logger.info("Disconnected.")
        time.sleep(2)
        self.q_listener.stop()



#for test purposes
if __name__ == "__main__":
    client = Client(input("Insert nickname: "), "blue")
    client.start()
    time.sleep(1)

    while client.running.is_set():
        client.logger.debug("Waiting for input.")
        msg = input("> ")
        client.handle_input(msg.rstrip())
        time.sleep(0.3)
    