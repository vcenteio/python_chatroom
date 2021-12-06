from constants import *
from message import *


class NetworkAgent():
    def __init__(self, s: socket.socket, logger: logging.Logger = None):
        self.s = s
        self.logger = logger

    def send(self, data: bytes) -> None:
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
            if self.logger:
                self.logger.error(ErrorDescription._FAILED_HEADER)
                self.logger.debug(f"Struct error. Description: {e}")
            raise SendError
        
        try:
            self.s.sendall(header + data)
        except (OSError, ConnectionError) as e:
            if self.logger:
                self.logger.error(ErrorDescription._FAILED_TO_SEND)
                self.logger.debug(f"Description: {e}")
            raise CriticalTransferError

    def receive_message_lenght(self) -> int:
        header = self.s.recv(HEADER_SIZE)
        if header:
            msg_length = struct.unpack(
                    HEADER_FORMAT, 
                    header
                )[0]
        else:
            raise EmptyHeader

        return msg_length

    def receive_message_data(self, msg_length: int) -> bytes:
        if msg_length:
            data = []
            count = 0
            while count < msg_length:
                buffer = self.s.recv(RECV_BLOCK_SIZE)
                count += len(buffer)
                data.append(buffer)
            return b"".join(data)
        else:
            raise NullMessageLength

    def receive(self) -> bytes:
        try:
            msg_length = self.receive_message_lenght()
            message_data = self.receive_message_data(msg_length)
            return message_data
        except (EmptyHeader, NullMessageLength) as e:
            if self.logger:
                self.logger.error(ErrorDescription._FAILED_RECV)
            raise ReceiveError(e)
        except struct.error as e:
            if self.logger:
                self.logger.error(ErrorDescription._MSG_LENGTH_ERROR)
            raise ReceiveError(e)
        except (OSError, ConnectionError) as e:
            if self.logger:
                self.logger.error(ErrorDescription._FAILED_RECV)
            raise CriticalTransferError(e)
        
    def can_receive_from(self) -> bool:
        readable, _, _ = select.select((self.s,), (), (), 0.5)
        return True if self.s in readable else False
    
    def can_send_to(self) -> bool:
        _, writeable, _ = select.select((), (self.s,), (), 0.5)
        return True if self.s in writeable else False