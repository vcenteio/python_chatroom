from constants import *
from message import *
from abc import ABC, abstractmethod
from logging import Logger
from socket import socket as socket, AF_INET, SOCK_STREAM, SHUT_RDWR

class NetworkDataTransferer(ABC):
    '''
    Abstract Base Class for DataTransferer classes.
    '''
    _socket: socket
    logger: Logger
    
    @abstractmethod
    def send(self, data: bytes) -> None:
        ...

    @abstractmethod
    def receive_message_lenght(self) -> int:
        ...

    @abstractmethod
    def receive_message_data(self, msg_length: int) -> bytes:
        ...

    @abstractmethod
    def receive(self) -> bytes:
        ...

    @abstractmethod
    def can_receive_from(self) -> bool:
        ...
    
    @abstractmethod
    def can_send_to(self) -> bool:
        ...
    
    @abstractmethod
    def close_socket(self) -> None:
        ...

class TCPIPv4DataTransferer(NetworkDataTransferer):
    def __init__(self, _socket: socket = None, logger: Logger = None):
        if _socket:
            self._socket = _socket
        else:
            self._socket = socket(AF_INET, SOCK_STREAM)
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
            self._socket.sendall(header + data)
        except (OSError, ConnectionError) as e:
            if self.logger:
                self.logger.error(ErrorDescription._FAILED_TO_SEND)
                self.logger.debug(f"Description: {e}")
            raise CriticalTransferError

    def receive_message_lenght(self) -> int:
        header = self._socket.recv(HEADER_SIZE)
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
                buffer = self._socket.recv(RECV_BLOCK_SIZE)
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
        readable, _, _ = select.select((self._socket,), (), (), 0.5)
        return True if self._socket in readable else False
    
    def can_send_to(self) -> bool:
        _, writeable, _ = select.select((), (self._socket,), (), 0.5)
        return True if self._socket in writeable else False

    def close_socket(self):
        if self.logger: self.logger.debug("Closing socket.")
        try:
            self._socket.shutdown(SHUT_RDWR)
        except OSError:
            pass
        try:
            self._socket.close()
            if self.logger: self.logger.debug("Socket closed.")
            return True
        except OSError as e:
            if self.logger: self.logger.debug(
                "Socket already closed. "\
                f"Error description: {e}"
            )
            return False