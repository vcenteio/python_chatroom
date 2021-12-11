from abc import ABC, abstractmethod
from constants import *
from exceptions import *
from message import *
from cryptography.fernet import InvalidToken
from cryptography.fernet import Fernet
from cryptography.exceptions import *
import base64
from base64 import urlsafe_b64encode, urlsafe_b64decode
import secrets
from secrets import token_bytes
import random
import math

class Cryptographer(ABC):
    logger: logging.Logger

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        ...
    
    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        ...
    
    @abstractmethod
    def export_encryption_keys(self) -> bytes:
        ...
    
    @abstractmethod
    def import_decryption_keys(self, _buffer: bytes) -> bytes:
        ...

class RSAFernetCryptographer(Cryptographer):
    def __init__(
            self,
            logger: logging.Logger = None
        ):
        self.public_key, self.private_key = self.generate_rsa_keys()
        self.d_fernet_key = self.generate_fernet_key() 
        self.d_fernet = Fernet(self.d_fernet_key)
        self.logger = logger

    F_KEY_SZ = len(urlsafe_b64encode(bytes(32))) # fernet key size
    DUMMY_SZ = 2048 # dummy bytes size
    ENC_DUMMY_SZ = len(urlsafe_b64encode(bytes(DUMMY_SZ))) # dummy encoded size
    PCKD_PK_SZ = struct.calcsize("<ii") # packed public key size
    ENCR_KEYS_SZ = len( # encypted keys size
        Fernet(Fernet.generate_key()).encrypt(bytes(PCKD_PK_SZ+F_KEY_SZ))
    ) 
    BYTES_SEPARATOR = b"$_-_$"

    def export_encryption_keys(self) -> bytes:
        if self.logger:
            self.logger.debug("Exporting encryption keys.")
            self.logger.debug(f"RSA key: {self.public_key}")
            self.logger.debug(f"Fernet key: {self.d_fernet_key}")
        temp_key = self.generate_fernet_key()
        packed_public_key = struct.pack("<ii", *self.public_key)
        prefix = urlsafe_b64encode(token_bytes(self.DUMMY_SZ))
        sufix = urlsafe_b64encode(token_bytes(self.DUMMY_SZ))
        encrypted_keys = Fernet(temp_key).encrypt(
            packed_public_key+self.d_fernet_key
        )
        return b"".join([prefix, temp_key, encrypted_keys, sufix])
    
    def import_decryption_keys(self, _buffer: bytes) -> bytes:
        temp_key_pos_start = self.ENC_DUMMY_SZ
        temp_key_pos_end = temp_key_pos_start + self.F_KEY_SZ
        enc_keys_pos_start = temp_key_pos_end
        enc_keys_pos_end = enc_keys_pos_start + self.ENCR_KEYS_SZ
        pks = self.PCKD_PK_SZ

        if self.logger: self.logger.debug("Importing decryption keys. ")
        temp_key = _buffer[temp_key_pos_start:temp_key_pos_end]
        encrypted_keys = _buffer[enc_keys_pos_start:enc_keys_pos_end]
        decrypted_keys = Fernet(temp_key).decrypt(encrypted_keys)
        self.e_public_key = struct.unpack("<ii", decrypted_keys[:pks])
        self.e_fernet_key = decrypted_keys[pks:]
        self.e_fernet = Fernet(self.e_fernet_key)
        if self.logger:
            self.logger.debug(f"Imported RSA key: {self.e_public_key}")
            self.logger.debug(f"Imported Fernet key: {self.e_fernet_key}")

    def encrypt(self, data: bytes) -> bytes:
        return self.e_fernet.encrypt(self.rsa_encrypt_b(data))

    def decrypt(self, data: bytes) -> bytes:
        try:
            return self.rsa_decrypt_b(self.d_fernet.decrypt(data))
        except (InvalidToken, InvalidSignature) as e:
            self.logger.exception(e)
            raise EncryptionError(e)

    @staticmethod
    def generate_fernet_key():
        return urlsafe_b64encode(secrets.token_bytes(32))

    @staticmethod
    def generate_rsa_keys():
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
        s = urlsafe_b64encode(s)
        encrypted_s = []
        e, N = self.e_public_key
        for l in s:
            enc_l = (l ** e) % N
            encrypted_s.append(struct.pack("<d", enc_l))
        return urlsafe_b64encode(self.BYTES_SEPARATOR.join(encrypted_s))

    def rsa_decrypt_b(self, s: bytes) -> bytes:
        s = urlsafe_b64decode(s).split(self.BYTES_SEPARATOR)
        decrypted_s = []
        d, N = self.private_key 
        for l in s:
            l_int = int(struct.unpack("<d", l)[0])
            dec_l = (l_int ** d) % N
            decrypted_s.append(dec_l.to_bytes(1, "little"))
        return urlsafe_b64decode(b"".join(decrypted_s))