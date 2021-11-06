﻿from server import ClientEntry
from transferlib import *
from constants import *


class Client(NetworkAgent):
    def __init__(self, nickname: str, color: str):
        super().__init__()
        self.nickname = nickname
        self.color = color # hex nickname color
        self.command_queue = queue.Queue(10)
        self.reply_queue = queue.Queue(10)
        self.server_broadcast_queue = queue.Queue()
        self.ID = int() # determined by the server later
        self.address = tuple() # obtained later when connection get's stabilished
        self.server_public_key = tuple() # obtained later
        self.fernet_key = b"" #obtained later

    def write_to_chatbox(self):
        while self.running.is_set():
            message = self.server_broadcast_queue.get()
            #for now just print
            print(f"[SERVER BROADCAST] (Command: {message.code}) {message._from}: {message.data}")

    def handle_receive(self):
        while self.running.is_set():
            buffer = self.decrypt(
                self.receive(self.socket),
                self.fernet_key,
                self.private_key
            )
            message = ClientMessage.unpack(buffer)
            if message.code == Command.ERROR:
                print(message)
            else:
                self.server_broadcast_queue.put(message)
    
    def handle_send(self, data: bytes):
        message = ClientMessage(Command.SEND, self.nickname, data.decode())
        self.send(self.socket, self.encrypt(message.pack(), self.fernet_key, self.server_public_key))

    def handle_connect(self, server_ip, server_port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = self.socket.connect((server_ip, server_port))
    
    def run(self):
        self.handle_connect(server_IP, server_Port)
        self.running.set()
        print("[CLIENT] My public key:", self.public_key)

        # receive server public key
        buffer = self.receive(self.socket).decode().split("-")
        self.server_public_key = (int(buffer[0]), int(buffer[1]))
        print("[CLIENT] Server public key:", self.server_public_key)
        
        # send public key to server
        self.send(self.socket, f"{self.public_key[0]}-{self.public_key[1]}".encode())

        # receive encrypted fernet and HMAC keys
        self.fernet_key = self.rsa_decrypt_b(self.receive(self.socket), self.private_key)
        print("[CLIENT] Fernet key:", self.fernet_key)
        self.hmac_key = self.rsa_decrypt_b(self.receive(self.socket), self.private_key)
        print("[CLIENT] HMAC key:", self.hmac_key)


        # send ecrypted client data 
        initial_data = json.dumps({"nickname": self.nickname, "color": self.color})
        self.send(self.socket, self.rsa_encrypt_b(initial_data.encode(), self.server_public_key))

        # receive ID generated by the server
        self.ID = struct.unpack("<I", self.decrypt(self.receive(self.socket), self.fernet_key, self.private_key))[0]
        print("[CLIENT] My ID:", self.ID)


        threading.Thread(target=self.write_to_chatbox, daemon=True).start()
        threading.Thread(target=self.handle_receive, daemon=True).start()


#for test purposes
if __name__ == "__main__":
    client = Client(input("Insert nickname: "), "blue")
    
    threading.Thread(target=client.run, daemon=True).start()
    # print("RSA keys:", client.public_key, client.private_key)

    while True:
        time.sleep(0.3)
        msg = input("> ")
        client.handle_send(msg.rstrip().encode())