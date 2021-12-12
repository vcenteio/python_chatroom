

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
    def __init__(self, msg):
        self.msg = msg if msg else "Socket connection broken."
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
    def __init__(self, msg, type):
        self.msg = msg if msg else f"Wrong type: {type}. Should be bytes."
        super().__init__(self.msg)

# pack/unpack errors
class MessagePackError(Exception):
    def __init__(self, msg):
        self.msg = msg if msg else "Unable to pack message."
        super().__init__(self.msg)

class MessageUnpackError(Exception):
    def __init__(self, msg, *args):
        self.msg = msg if msg else f"Unable to unpack message. Args: {args}"
        super().__init__(msg, *args)

class UnknownMessageType(MessageUnpackError):
    def __init__(self, msg=None, type=None):
        self.msg = msg if msg else "Unknown message type."
        self.type = type
        super().__init__(self.msg, type)

class MessageWithNoType(MessageUnpackError):
    def __init__(self, msg: str, msg_dict: dict):
        super().__init__(msg, msg_dict)

class IntegrityCheckFailed(MessageUnpackError):
    def __init__(self, msg):
        self.msg = msg if msg else "Integrity check failed."
        super().__init__(self.msg)

# encryption errors
class EncryptionError(ValueError):
    def __init__(self, msg):
        super().__init__(msg)

class InvalidDataForEncryption(EncryptionError):
    def __init__(self, msg):
        self.msg = msg if msg else "Wrong value for encryption/decryption."
        super().__init__(self.msg)

class InvalidRSAKey(EncryptionError):
    def __init__(self):
        self.msg = "Invalid RSA keys."
        super().__init__(self.msg)