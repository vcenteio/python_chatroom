from logging import handlers
from cryptography.fernet import InvalidToken
from cryptography.fernet import Fernet
from cryptography.exceptions import *
from cryptographer import Cryptographer
from message import *
import logger


class NetworkAgent(threading.Thread):
    address = tuple()
    # running = threading.Event()
    public_key, private_key = Cryptographer.generate_rsa_keys()
    running: bool
    fernet_key: bytes 
    hmac_key: bytes
    logging_q = queue.Queue()

    def send(self, s: socket.socket, data: bytes) -> bool:
        """
        Pack data with header containing message length and send it.
        """
        if not data:
            raise NullData
        
        if not isinstance(data, bytes):
            raise NonBytesData

        try:
            header = struct.pack(HEADER_FORMAT, len(data))
        except struct.error as e:
            if self.running:
                self.logger.error(ErrorDescription._FAILED_HEADER)
                self.logger.debug(f"Struct error. Description: {e}")
            raise SendError
        
        try:
            s.sendall(header + data)
        except (OSError, ConnectionError) as e:
            if self.running:
                self.logger.error(ErrorDescription._FAILED_TO_SEND)
                self.logger.debug(f"OSError. Description: {e}")
            raise CriticalTransferError

    def receive_message_lenght(self, s: socket.socket) -> int:
        header = s.recv(HEADER_SIZE)
        if header:
            msg_length = struct.unpack(
                    HEADER_FORMAT, 
                    header
                )[0]
        else:
            raise EmptyHeader

        return msg_length

    def receive_message_data(self, s: socket.socket, msg_length: int) -> bytes:
        if msg_length:
            data = []
            count = 0
            while count < msg_length:
                buffer = s.recv(RECV_BLOCK_SIZE)
                count += len(buffer)
                data.append(buffer)
            return b"".join(data)
        else:
            raise NullMessageLength

    def receive(self, s: socket.socket) -> bytes:
        try:
            msg_length = self.receive_message_lenght(s)
            message_data = self.receive_message_data(s, msg_length)
            return message_data
        except (EmptyHeader, NullMessageLength) as e:
            if self.running:
                self.logger.error(ErrorDescription._FAILED_RECV)
                self.logger.debug(e)
            raise ReceiveError(e)
        except struct.error as e:
            if self.running:
                self.logger.error(ErrorDescription._MSG_LENGTH_ERROR)
                self.logger.debug(f"Struct error. Description: {e}")
            raise ReceiveError
        except (OSError, ConnectionError) as e:
            if self.running:
                self.logger.error(ErrorDescription._FAILED_RECV)
                self.logger.debug(f"OSError. Description: {e}")
            raise CriticalTransferError
        
    @staticmethod
    def can_receive_from(s: socket.socket) -> bool:
        readable, _, _ = select.select((s,), (), (), 0.5)
        return True if s in readable else False
    
    @staticmethod
    def can_send_to(s: socket.socket) -> bool:
        _, writeable, _ = select.select((), (s,), (), 0.5)
        return True if s in writeable else False

    def setup_logger(self):
        self.logger = logger.get_new_logger(self.name)
        self.logger.addHandler(
            handlers.QueueHandler(self.logging_q)
        )
        self.q_listener = handlers.QueueListener(
            self.logging_q,
            logger.get_stream_handler(),
            logger.get_file_handler(self.name)
        )
        self.q_listener.respect_handler_level = True

    def terminate_thread(self, t: threading.Thread, q: queue.Queue = None):
        thread_name = t.name.lower()
        if q:
            if t.is_alive():
                self.logger.debug(f"Sent terminate command to {t.name.lower()} queue.")
                q.put(QueueSignal._terminate_thread) 
            self.logger.debug(f"Joining {thread_name} queue.")
            q.join()
            self.logger.debug(f"{thread_name} queue joined.")
        if t.is_alive():
            try:
                self.logger.debug(f"Joining {thread_name} thread.")
                t.join()
                self.logger.debug(f"{thread_name} thread joined.")
            except RuntimeError:
                pass
        self.logger.debug(f"{t.name.lower()} thread terminated.")

    def close_socket(self, s: socket.socket):
        self.logger.debug("Closing socket.")
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            s.close()
            self.logger.debug("Socket closed.")
            return True
        except OSError as e:
            self.logger.debug("Socket already closed.")
            self.logger.debug(f"Error description: {e}")
            return False