﻿from message import *

class NetworkAgent:
    def __init__(self):
        self.address = tuple()
        self.running = threading.Event()
        self.public_key, self.private_key = self.generate_rsa_keys()
        self.fernet_key = b""
        self.hmac_key = b""

    @staticmethod
    def send(socket: socket.socket, data: bytes):
        """
        Pack data with header containing message lenght and send it.
        """
        header = struct.pack(HEADER_FORMAT, len(data))
        socket.sendall(header + data)

    @staticmethod
    def receive(socket: socket.socket) -> bytes:
        """
        Receive header with the message lenght and use it to receive the message content.
        """
        msg_lenght = struct.unpack(HEADER_FORMAT, socket.recv(HEADER_SIZE))[0]
        return socket.recv(msg_lenght)

    def encrypt(self, data: bytes) -> bytes:
        return Fernet(self.fernet_key).encrypt(base64.urlsafe_b64encode(data))

    def decrypt(self, data: bytes) -> bytes:
        return base64.urlsafe_b64decode(Fernet(self.fernet_key).decrypt(data))

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