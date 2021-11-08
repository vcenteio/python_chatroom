﻿import time
import sys
import random
import struct
import socket
import queue
import threading
import json
import pickle
import hashlib
import base64
import math
import hmac
from cryptography.fernet import Fernet
from constants import *


class Command:
    SEND, DISCONNECT, ERROR, SUCCESS = range(4)

class ClientMessage:

    id_count = 1
    CLIENT_ID = int()

    def __init__(self, code: int, _from: str, data=None, _id=None):
        self.code = code
        self._from = _from
        self.data = data
        self.id = self.generate_id() if _id == None else _id
        self.time = time.asctime()
    
    @classmethod
    def generate_id(cls):
        if cls.id_count < 100000:
            _id = f"#{cls.id_count:05}@{cls.CLIENT_ID}"
            cls.id_count += 1
            return _id

    def pack(self, hmac_key: bytes):
        serialized = json.dumps({
            'code': self.code,
            'from': self._from,
            'data': self.data,
            'id': self.id,  
            'time': self.time
        }).encode()
        msg_hash = hmac.new(hmac_key, serialized, hashlib.sha256).digest()
        return msg_hash + serialized

    @staticmethod
    def unpack(buffer: bytes, hmac_key: bytes):
        msg_hash = buffer[:HASH_SIZE] 
        msg_buffer = buffer[HASH_SIZE:] 
        new_hash = hmac.new(hmac_key, msg_buffer, hashlib.sha256).digest()
        if msg_hash == new_hash:
            msg_dict = json.loads(msg_buffer)
            return ClientMessage(msg_dict["code"], msg_dict["from"], msg_dict["data"], msg_dict["id"])
        else:
            return ClientMessage(Command.ERROR, "_server", "[SERVER] Integrity check failed.")

    def __str__(self) -> str:
        return self.data


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