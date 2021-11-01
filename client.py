﻿from server import ClientEntry
from transferlib import *
from constants import *



class Client:
    def __init__(self, nickname: str, color: str):
        self.nickname = nickname
        self.color = color # hex nickname color
        self.command_queue = queue.Queue(10)
        self.reply_queue = queue.Queue(10)
        self.server_broadcast_queue = queue.Queue()
        self.running = threading.Event()

    def write_to_chatbox(self):
        while self.running.is_set():
            message = self.server_broadcast_queue.get()
            #for now just print
            print(f"[SERVER BROADCAST] (Command: {message.code}) {message._from}: {message.data}")

    def handle_receive(self):
        while self.running.is_set():
            buffer = json.loads(receive(self.socket))
            message = ClientMessage(buffer["code"], buffer["from"], buffer["data"])
            self.server_broadcast_queue.put(message)
    
    def handle_send(self, data: bytes):
        message = ClientMessage(Command.SEND, self.nickname, data.decode())
        self.socket.sendall(message.pack())

    def handle_connect(self, server_ip, server_port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((server_ip, server_port))
    
    def run(self):
        self.handle_connect(server_IP, server_Port)
        self.running.set()

        initial_data = json.dumps({"nickname": self.nickname, "color": self.color})
        send(self.socket, initial_data.encode())

        threading.Thread(target=self.write_to_chatbox, daemon=True).start()
        threading.Thread(target=self.handle_receive, daemon=True).start()


#for test purposes
if __name__ == "__main__":
    client = Client(input("Insert nickname: "), "blue")
    print(server_IP)
    threading.Thread(target=client.run, daemon=True).start()

    while True:
        time.sleep(0.1)
        msg = " ".join(input("Insert message: ").split("\n"))
        client.handle_send(msg.rstrip().encode())