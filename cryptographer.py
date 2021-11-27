from cryptography import fernet
from constants import *
from exceptions import *
from message import *
from cryptography.fernet import InvalidToken
from cryptography.fernet import Fernet
from cryptography.exceptions import *
import base64
import random
import math

class Cryptographer():
    def __init__(
            self,
            rsa_private_key: tuple,
            rsa_public_key: tuple,
            fernet_key: bytes,
            logger: logging.Logger
        ):
        self.private_key = rsa_private_key
        self.public_key = rsa_public_key
        self.fernet_key = fernet_key
        self.logger = logger

    def encrypt(self, data: bytes) -> bytes:
        if data == False or data == None:
            self.logger.debug("Got wrong data.")
            raise InvalidDataForEncryption
        
        # if not key:
        #     self.logger.debug("Got invalid key.")
        #     raise InvalidRSAKey

        return  Fernet(self.fernet_key).encrypt(
                    base64.urlsafe_b64encode(
                        self.rsa_encrypt_b(
                            base64.urlsafe_b64encode(data)
                        )
                    )
                )

    def decrypt(self, data: bytes) -> bytes:
        if data == False or data == None:
            self.logger.debug("Got wrong data.")
            raise InvalidDataForEncryption
        
        # if not key:
        #     self.logger.debug("Got invalid key.")
        #     raise InvalidRSAKey

        try:
            decrypted_data =  base64.urlsafe_b64decode(
                        self.rsa_decrypt_b(
                            base64.urlsafe_b64decode(
                                Fernet(self.fernet_key).decrypt(data)
                            )
                        )
                    )
            return decrypted_data
        except (InvalidToken, InvalidSignature) as e:
            self.logger.debug(e)
            raise EncryptionError("Invalid Fernet token.")

    @classmethod
    def generate_rsa_keys(self):
        # generate prime numbers
        primes = []
        for x in range(10, 100):
            is_prime = True 
            for y in range(2, x):
                if x % y == 0:
                    is_prime = False
                    break
            if is_prime:
                primes.append(x)
        # choose random prime values for p and q, assuring that q != p
        p = random.choice(primes)
        while (q := random.choice(primes)) == p:
            q = random.choice(primes)
        # calculate N and T
        N = p * q
        T = (p-1) * (q-1)
        # generate possible values for e that are smaller than T and coprime with T and N
        es = []
        for i in range(2, T):
            if math.gcd(T, i) == 1 and math.gcd(N, i) == 1:
                es.append(i)
        # choose a random value for e
        e = random.choice(es)
        # find an integer value for d
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
            self.logger.debug(" ".join([p, q, N, T, e, d]))
            return None
        return (pk, privkey)

    def rsa_encrypt(self, s: str) -> str:
        encrypted_s = []
        e, N = self.public_key
        for l in s:
            enc_l = chr((ord(l) ** e) % N)
            encrypted_s.append(enc_l)
        return "".join(encrypted_s)

    def rsa_decrypt(self, s: str) -> str:
        decrypted_s = []
        d, N = self.private_key 
        for l in s:
            dec_l = chr((ord(l) ** d) % N)
            decrypted_s.append(dec_l)
        return "".join(decrypted_s)
    
    def rsa_encrypt_b(self, s: bytes) -> bytes:
        DEBUG = 0
        encrypted_s = []
        e, N = self.public_key
        if DEBUG: print(f'DEGUB: e: {e} {type(e)}, N: {N} {type(N)}')
        for l in s:
            enc_l = (l ** e) % N
            encrypted_s.append(struct.pack("<d", enc_l))
        return BYTES_SEPARATOR.join(encrypted_s)

    def rsa_decrypt_b(self, s: bytes) -> bytes:
        DEBUG = 0
        s = s.split(BYTES_SEPARATOR)
        decrypted_s = []
        d, N = self.private_key 
        if DEBUG: print(f'DEGUB: d: {d} {type(d)}, N: {N} {type(N)}')
        for l in s:
            if DEBUG: print(l)
            l_int = int(struct.unpack("<d", l)[0])
            dec_l = (l_int ** d) % N
            decrypted_s.append(dec_l.to_bytes(1, "little"))
        return b"".join(decrypted_s)