﻿from message import *
from constants import *
from network_agent import NetworkAgent


class Client(NetworkAgent):
    def __init__(self, nickname: str, color: str):
        super().__init__()
        self.nickname = nickname
        self.color = color # hex nickname color
        self.dispatch_q = queue.Queue()
        self.chatbox_q = queue.Queue()
        self.ID = int() # determined by the server later
        self.server_public_key = tuple() # obtained later

    def write_to_chatbox(self):
        while self.running.is_set():
            message = self.chatbox_q.get()
            #for now just print
            print(
                f"[SERVER] ID: {message._id}",
                f"{message._from[1]} (ID: {message._from[0]}):",
                f"{message._data}"
            )
            self.chatbox_q.task_done()

    def dispatch(self):
        while self.running.is_set():
            message = self.dispatch_q.get()
            try:
                self.send(
                    self.socket,
                    self.encrypt(
                        message.pack(self.hmac_key),
                        self.server_public_key
                    )
                )
            except OSError:
                print("[OS ERROR]")
            time.sleep(CLT_SEND_SLEEP_TIME)
            self.dispatch_q.task_done()

    def handle_receive(self):
        while self.running.is_set():
            try:
                if self.can_receive_from(self.socket):
                    buffer =    self.decrypt(
                                    self.receive(self.socket),
                                    self.private_key
                                )
                else:
                    continue
                message = Message.unpack(buffer, self.hmac_key)
                if isinstance(message, Command):
                    if message._code == Command.BROADCAST:
                        reply = Reply(
                            Reply.SUCCESS,
                            (self.ID, self.nickname),
                            SERVER_ID,
                            message._id,
                            Reply.description[Reply._SUCCESSFULL_RECV]
                        )
                        self.chatbox_q.put(message)
                        self.dispatch_q.put(reply)
                elif isinstance(message, Reply):
                    print(
                        f"[SERVER {message._type.upper()}]",
                        f"(Msg ID: {message._message_id})",
                        f"{message}"
                    )
            # it's an error generated by the unpack function
            except IntegrityCheckFailed:
                reply = Reply(
                            Reply.UNPACK_ERROR,
                            (self.ID, self.nickname),
                            client.ID,
                            "-",
                            Reply.description[Reply._INTEGRITY_FAILURE]
                        )
                self.dispatch_q.put(reply)
            except UnknownMessageType:
                reply = Reply(
                            Reply.UNPACK_ERROR,
                            (self.ID, self.nickname),
                            client.ID,
                            "-",
                            Reply.description[Reply._UNKNOWN_MSG_TYPE]
                        )
                self.dispatch_q.put(reply)
            except struct.error:
                # client disconnect here
                sys.exit()
            except OSError:
                sys.exit()
            
            time.sleep(CLT_RECV_SLEEP_TIME)
    
    def handle_input(self, data: str):
        if data == "c:shut":
            message = Command(
                        Command.SHUTDOWN,
                        (self.ID, self.nickname),
                        data,
                    )
            self.dispatch_q.put(message)
            time.sleep(1)
            self.running.clear()
        elif data == "c:disc":
            self.handle_disconnect()
        else:
            message = Command(
                        Command.BROADCAST,
                        (self.ID, self.nickname),
                        data,
                    )
            self.dispatch_q.put(message)

    def handle_connect(self, server_ip, server_port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = self.socket.connect((server_ip, server_port))
        
    def handle_disconnect(self):
        print("[CLIENT] Disconnecting.")
        disconnect_cmd = Command(
                    Command.DISCONNECT,
                    (self.ID, self.nickname),
                    "Disconnect me.",
                )
        self.dispatch_q.put(disconnect_cmd)
        time.sleep(1)
        self.running.clear()
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
        except OSError:
            print("[CLIENT] Socket already closed.")
        self.dispatch_q.join()
        self.chatbox_q.join()
        sys.exit()
    
    def run(self):
        DEBUG = 1
        self.running.set()
        self.handle_connect(SERVER_IP, SERVER_PORT)
        if DEBUG: print("[CLIENT] My public key:", self.public_key)

        # receive server public key
        buffer = self.receive(self.socket).decode().split("-")
        self.server_public_key = (int(buffer[0]), int(buffer[1]))
        if DEBUG: print("[CLIENT] Server public key:", self.server_public_key)
        
        # send public key to server
        self.send(
            self.socket,
            f"{self.public_key[0]}-{self.public_key[1]}".encode()
        )

        # receive encrypted fernet and HMAC keys
        self.fernet_key = self.rsa_decrypt_b(
                            self.receive(self.socket),
                            self.private_key
                        )
        if DEBUG: print("[CLIENT] Fernet key:", self.fernet_key)
        self.hmac_key = self.rsa_decrypt_b(
                            self.receive(self.socket),
                            self.private_key
                        )
        if DEBUG: print("[CLIENT] HMAC key:", self.hmac_key)

        # send ecrypted client data 
        initial_data =  json.dumps({
                            "nickname": self.nickname,
                            "color": self.color
                        })
        self.send(
            self.socket,
            self.rsa_encrypt_b(
                initial_data.encode(),
                self.server_public_key
            )
        )

        # receive ID generated by the server
        self.ID =   struct.unpack("<I",
                        self.decrypt(
                            self.receive(self.socket),
                            self.private_key
                        )
                    )[0]
        Message.CLIENT_ID = self.ID
        if DEBUG: print("[CLIENT] My ID:", self.ID)

        chatbox_thread = threading.Thread(target=self.write_to_chatbox, daemon=True).start()
        dispatch_thread = threading.Thread(target=self.dispatch, daemon=True).start()
        receive_thread = threading.Thread(target=self.handle_receive, daemon=True).start()


#for test purposes
if __name__ == "__main__":
    client = Client(input("Insert nickname: "), "blue")
    client.start()

    while client.running.is_set():
        time.sleep(0.3)
        msg = input("> ")
        client.handle_input(msg.rstrip())