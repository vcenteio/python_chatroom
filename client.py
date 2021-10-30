from transferlib import *
from constants import *
import sys



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
            print(f"[SERVER BROADCAST] (Command: {message['code']}) {message['from']}: {message['data']}")

    def handle_receive(self):
        while self.running.is_set():
            buffer = receive(self.socket)
            message = json.loads(buffer)
            self.server_broadcast_queue.put(message)

    
    def handle_send(self, data: str):
        message = ClientMessage(Command.SEND, self.nickname, data)
        self.socket.sendall(message.packed)

    def handle_connect(self, server_ip, server_port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((server_ip, server_port))
    
    def run(self):
        self.handle_connect(server_IP, server_Port)
        self.running.set()
        threading.Thread(target=self.write_to_chatbox, daemon=True).start()
        threading.Thread(target=self.handle_receive, daemon=True).start()


#for test purposes
if __name__ == "__main__":
    client = Client(input("Insert nickname: "), "blue")
    print(server_IP)
    threading.Thread(target=client.run, daemon=True).start()

    while True:
        time.sleep(0.1)
        msg = input("Insert message: ")
        client.handle_send(msg.rstrip())