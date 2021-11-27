from logging import handlers

from cryptography.fernet import InvalidToken
from cryptography.exceptions import *
from message import *
import logger

class NetworkAgent(threading.Thread):
    def __init__(self):
        super().__init__()
        self.address = tuple()
        self.running = threading.Event()
        self.public_key, self.private_key = self.generate_rsa_keys()
        self.fernet_key = b""
        self.hmac_key = b""
        self.logging_q = queue.Queue(-1) # queue with infinite size for logging

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


    def send(self, socket: socket.socket, data: bytes) -> bool:
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
            if self.running.is_set():
                self.logger.error(ErrorDescription._FAILED_HEADER)
                self.logger.debug(f"Struct error. Description: {e}")
            raise SendError

        try:
            socket.sendall(header + data)
        except (OSError, ConnectionError) as e:
            if self.running.is_set():
                self.logger.error(ErrorDescription._FAILED_TO_SEND)
                self.logger.debug(f"OSError. Description: {e}")
            raise CriticalTransferError
        
        return True


    @staticmethod
    def receive_message_lenght(socket: socket.socket) -> int:
        header = socket.recv(HEADER_SIZE)
        if header:
            msg_length = struct.unpack(
                    HEADER_FORMAT, 
                    header
                )[0]
        else:
            raise EmptyHeader

        if msg_length:
            return msg_length
        else:
            raise NullMessageLength

    @staticmethod    
    def receive_message_data(socket: socket.socket, msg_length: int) -> bytes:
        if msg_length:
            data = []
            count = 0
            while count < msg_length:
                buffer = socket.recv(RECV_BLOCK_SIZE)
                count += len(buffer)
                data.append(buffer)
            return b"".join(data)
        else:
            raise NullMessageLength

    def receive(self, socket: socket.socket) -> bytes:
        try:
            msg_length = self.receive_message_lenght(socket)
            message_data = self.receive_message_data(socket, msg_length)
            return message_data
        except (EmptyHeader, NullMessageLength) as e:
            if self.running.is_set():
                self.logger.error(ErrorDescription._FAILED_RECV)
                self.logger.debug(e)
            raise ReceiveError
        except struct.error as e:
            if self.running.is_set():
                self.logger.error(ErrorDescription._MSG_LENGTH_ERROR)
                self.logger.debug(f"Struct error. Description: {e}")
            raise ReceiveError
        except (OSError, ConnectionError) as e:
            if self.running.is_set():
                self.logger.error(ErrorDescription._FAILED_RECV)
                self.logger.debug(f"OSError. Description: {e}")
            raise CriticalTransferError
        
    @staticmethod
    def can_receive_from(s: socket.socket) -> bool:
        readable, _, _ = select.select([s], [], [], 0.5)
        return True if s in readable else False
    
    @staticmethod
    def can_send_to(s: socket.socket) -> bool:
        _, writeable, _ = select.select([], [s], [], 0.5)
        return True if s in writeable else False

    def receive_buffer(self, s: socket.socket):
        while not self.can_receive_from(s):
            continue
        return self.receive(s) 

    # encryption methods
    def encrypt(self, data: bytes, key: tuple) -> bytes:
        if data == False or data == None:
            self.logger.debug("Got wrong data.")
            raise InvalidDataForEncryption
        
        if not key:
            self.logger.debug("Got invalid key.")
            raise InvalidRSAKey

        return  Fernet(self.fernet_key).encrypt(
                    base64.urlsafe_b64encode(
                        self.rsa_encrypt_b(
                            base64.urlsafe_b64encode(data),
                            key
                        )
                    )
                )

    def decrypt(self, data: bytes, key: tuple) -> bytes:
        if data == False or data == None:
            self.logger.debug("Got wrong data.")
            raise InvalidDataForEncryption
        
        if not key:
            self.logger.debug("Got invalid key.")
            raise InvalidRSAKey

        try:
            decrypted_data =  base64.urlsafe_b64decode(
                        self.rsa_decrypt_b(
                            base64.urlsafe_b64decode(
                                Fernet(self.fernet_key).decrypt(data)
                            ),
                            key
                        )
                    )
            return decrypted_data
        except (InvalidToken, InvalidSignature) as e:
            self.logger.debug(e)
            raise EncryptionError("Invalid Fernet token.")

    @staticmethod
    def generate_rsa_keys():
        # gerar números primos
        primes = []
        for x in range(10, 100):
            is_prime = True 
            for y in range(2, x):
                if x % y == 0:
                    is_prime = False
                    break
            if is_prime:
                primes.append(x)

        # escolher aleatoriamente valores primos para p e q, garantindo que q != p
        p = random.choice(primes)
        while (q := random.choice(primes)) == p:
            q = random.choice(primes)

        # calcular N e T
        N = p * q
        T = (p-1) * (q-1)

        # gerar possiveis valores para e, que deve ser menor que T e coprimo de T e N
        es = []
        for i in range(2, T):
            # if i % 2 != 0 and T % i != 0 and math.gcd(T, i) == 1:
            if math.gcd(T, i) == 1 and math.gcd(N, i) == 1:
                es.append(i)

        # escolher e aleatoriamente
        e = random.choice(es)

        # encontrar um valor para d que seja inteiro
        d = None
        for i in range(1, e):
            k = ((T * i) + 1) / e
            l = int(k)
            if k - l == 0.0:
                d = l
                break

        # create public and private keys
        pk = (e, N)
        privkey = (d,N)

        if not d:
            print(p, q, N, T, e, d)
            return None

        return (pk, privkey)

    @staticmethod
    def rsa_encrypt(s: str, key: tuple) -> str:
        encrypted_s = []
        e, N = key[0], key[1]
        for l in s:
            enc_l = chr((ord(l) ** e) % N)
            encrypted_s.append(enc_l)
        return "".join(encrypted_s)

    @staticmethod
    def rsa_decrypt(s: str, key: tuple) -> str:
        decrypted_s = []
        d, N = key[0], key[1]
        for l in s:
            dec_l = chr((ord(l) ** d) % N)
            decrypted_s.append(dec_l)
        return "".join(decrypted_s)
    
    @staticmethod
    def rsa_encrypt_b(s: bytes, key: tuple) -> bytes:
        DEBUG = 0
        encrypted_s = []
        e, N = key[0], key[1]
        if DEBUG: print(f'DEGUB: e: {e} {type(e)}, N: {N} {type(N)}')
        for l in s:
            enc_l = (l ** e) % N
            encrypted_s.append(struct.pack("<d", enc_l))
        return BYTES_SEPARATOR.join(encrypted_s)

    @staticmethod
    def rsa_decrypt_b(s: bytes, key: tuple) -> bytes:
        DEBUG = 0
        s = s.split(BYTES_SEPARATOR)
        decrypted_s = []
        d, N = key[0], key[1]
        if DEBUG: print(f'DEGUB: d: {d} {type(d)}, N: {N} {type(N)}')
        for l in s:
            if DEBUG: print(l)
            l_int = int(struct.unpack("<d", l)[0])
            dec_l = (l_int ** d) % N
            decrypted_s.append(dec_l.to_bytes(1, "little"))
        return b"".join(decrypted_s)
    
    
    