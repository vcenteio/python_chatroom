
    

class MessageUnpackError(Exception):
    def __init__(self, msg):
        super().__init__(msg)

class UnknownMessageType(MessageUnpackError):
    def __init__(self, msg=None):
        super().__init__(msg)

class IntegrityCheckFailed(MessageUnpackError):
    def __init__(self, msg=None):
        super().__init__(msg)