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

        # self.command_handlers = {
        #     ClientCommand.CONNECT : self.handle_connect,
        #     ClientCommand.SEND : self.handle_send,
        #     ClientCommand.RECEIVE : self.handle_receive,
        #     ClientCommand.DISCONNECT : self.handle_disconnect
        # }
    
    def write_to_chatbox(self):
        while self.running.is_set():
            message = self.server_broadcast_queue.get()
            #for now just print
            print(f"[SERVER BROADCAST] {message}")

    def handle_receive(self):
        while self.running.is_set():
            buffer = self.socket.recv(HEADER_SIZE)
            if len(buffer) == HEADER_SIZE:
                msg_lenght = get_header(buffer)
                message = self.socket.recv(msg_lenght).decode()
                self.server_broadcast_queue.put(message)
            else:
                print(f"[SERVER] Buffer lenght less than 4: {len(buffer)} {self.socket.fileno()} {self.socket.type} {self.socket.getblocking()}")
                self.running.clear()

    def handle_connect(self, server_ip, server_port):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((server_ip, server_port))
        except:
            self.reply_queue.put(ClientReply.SUCCESS)
    
    def handle_send(self, data: bytes):
        try:
            self.socket.sendall(data)
            self.reply_queue.put(ClientReply.SUCCESS)
        except:
            self.reply_queue.put(ClientReply.ERROR)
    
    def run(self):
        self.handle_connect(server_IP, server_Port)
        self.running.set()
        threading.Thread(target=self.write_to_chatbox, daemon=True).start()
        threading.Thread(target=self.handle_receive, daemon=True).start()


if __name__ == "__main__":
    client = Client(input("Insert nickname: "), "blue")
    print(server_IP)
    threading.Thread(target=client.run, daemon=True).start()


    while True:
        time.sleep(0.1)
        msg = input("Insert message: ")
        if msg != "cshut":
            packed_msg = create_header(len(msg)) + msg.encode()
            client.handle_send(packed_msg)
        else:
            sys.exit()