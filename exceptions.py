
    

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