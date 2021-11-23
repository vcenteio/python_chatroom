


class TransferError(Exception):
    def __init__(self, msg):
        super().__init__(msg)

class SendError(TransferError):
    def __init__(self, msg=None):
        self.msg = msg if msg else "Could not send data."
        super().__init__(msg)

class ReceiveError(TransferError):
    def __init__(self, msg=None):
        self.msg = msg if msg else "Could not receive data."
        super().__init__(msg)

class BrokenConnection(TransferError):
    def __init__(self, msg=None):
        self.msg = msg if msg else "Connection is broken."
        super().__init__(msg)

class NonSocket(TypeError):
    def __init__(self):
        self.msg = "Non socket type argument passed."
        super().__init__(self.msg)

class EmptyHeader(ValueError):
    def __init__(self):
        self.msg = "Got empty header."
        super().__init__(self.msg)
    
class CriticalTransferError(TransferError):
    def __init__(self):
        self.msg = "Socket connection broken."
        super().__init__(self.msg)

class NullMessageLength(ValueError):
    def __init__(self):
        self.msg = "Got null message length."
        super().__init__(self.msg)

class NullData(ValueError):
    def __init__(self):
        self.msg = "Data argument should not be 0."
        super().__init__(self.msg)

class NonBytesData(TypeError):
    def __init__(self, type):
        self.msg = f"Wrong type for data argument ({type}). Should be bytes."
        super().__init__(self.msg)

# unpacking errors
class MessageUnpackError(Exception):
    def __init__(self, msg):
        super().__init__(msg)

class UnknownMessageType(MessageUnpackError):
    def __init__(self, msg=None):
        super().__init__(msg)

class IntegrityCheckFailed(MessageUnpackError):
    def __init__(self):
        msg = "HMAC integrity check failed."
        super().__init__(msg)


# encryption errors
class EncryptionError(ValueError):
    def __init__(self, msg):
        super().__init__(msg)

class InvalidDataForEncryption(EncryptionError):
    def __init__(self):
        self.msg = "Wrong value passed as argument."
        super().__init__(self.msg)

class InvalidRSAKey(EncryptionError):
    def __init__(self):
        self.msg = "Invalid RSA keys."
        super().__init__(self.msg)