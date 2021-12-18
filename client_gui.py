from message import *
from constants import *
from time import sleep
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import colorchooser
from threading import Thread
from queue import Queue
from client import Client
from logging import handlers
from cryptographer import Cryptographer, RSAFernetCryptographer
from transfer import NetworkDataTransferer, TCPIPv4DataTransferer
import logger
import re


class ClientGui():
    def __init__(self, data_transferer: NetworkDataTransferer,
    cryptographer: Cryptographer, msg_guardian: MessageGuardian
    ):
        self.data_transferer = data_transferer
        self.crypt = cryptographer
        self.msg_guardian = msg_guardian

    root = Tk()
    root.title("Python Chatroom")
    name = "CLIENT_GUI"

    # Configure the window size and position
    screen_width = root.winfo_screenwidth()
    screen_height= root.winfo_screenheight()
    window_width = 600
    window_height = 400
    center_x = int(screen_width/2 - window_width/2)
    center_y = int(screen_height/2 - window_height/2)
    root.geometry(f"{window_width}x{window_height}+{center_x}+{center_y}")
    root.resizable(False, False)
    try:
        root.iconbitmap(".\chat_icon.ico")
    except:
        pass

    logging_q = Queue()
    nickname_color: str = None
    lc = 1 # line count for the nickname color tag
    connected: bool = False
            
    def message_box_clean(self):
        self.message_box_text.delete("1.0", END)
        self.message_box_text.focus()

    def write_to_chat_box(self):
        active = True
        while active:
            message: Message = self.client.message_output_q.get()
            if isinstance(message, Command):
                try:
                    ncts = [
                        f'{self.lc}.0',
                        f'{self.lc}.{len(message._from[1])}'
                    ]
                    self.chat_box_text.tag_config(
                        f'{message._from[1]}_color',
                        foreground=message._nick_color
                    )
                    self.chat_box_text.config(state="normal")
                    self.chat_box_text.insert(
                        "end",
                        m := f'{message._from[1]}: {message}\n'
                    )
                    self.chat_box_text.tag_add(
                        f'{message._from[1]}_color',
                        ncts[0], ncts[1]
                    )
                    self.chat_box_text.yview("end")
                    self.chat_box_text.config(state="disabled")
                    self.lc += m.count("\n")
                except:
                    self.chat_box_text.config(state="normal")
                    self.chat_box_text.insert(
                        "end",
                        m := f"{message._data}\n"
                    )
                    self.chat_box_text.yview("end")
                    self.chat_box_text.config(state="disabled")
                    self.lc += m.count("\n")
            elif message is QueueSignal._terminate_thread:
                active = False
            self.client.message_output_q.task_done()
        self.logger.debug("Exiting chatbox writer loop.")

    def kbsend(self, dummy):
        message = self.message_box_text.get(1.0, "end")
        self.client.handle_input(message)
        self.message_box_clean()
    
    def set_gui_state_to_connection_established(self):
        self.message_send_btn.config(state="enabled")
        self.server_disconnect_btn.config(state="enabled")
        self.server_connect_btn.config(state="disabled")
        self.color_btn.config(state="disabled")
        self.message_box_text.config(state="normal")
        self.ip_entry.config(state="disabled")
        self.port_entry.config(state="disabled")
        self.nickname_entry.config(state="disabled")
        self.message_box_text.focus()
        self.root.bind("<Control-Return>", self.kbsend)

    def set_gui_state_to_disconnected(self):
        self.message_send_btn.config(state="disabled")
        self.server_disconnect_btn.config(state="disabled")
        self.server_connect_btn.config(state="enabled")
        self.color_btn.config(state="enabled")
        self.message_box_text.config(state="disabled")
        self.ip_entry.config(state="enabled")
        self.port_entry.config(state="enabled")
        self.nickname_entry.config(state="enabled")
        self.root.unbind("<Control-Return>")

    def choose_color(self):
        self.nickname_color = colorchooser.askcolor()[1]

    @staticmethod
    def is_valid_ip(ip):
        pattern = re.compile(
            r'^([1-9]|[1-9]\d|[1-9]\d\d).'
            + r'(\d|[1-9]\d|[1-9]\d\d).'
            + r'(\d|[1-9]\d|[1-9]\d\d).'
            + r'(\d|[1-9]\d|[1-9]\d\d)$'
        )
        return bool(pattern.match(ip))

    @staticmethod
    def is_valid_port(port):
        return port > 1000 and port < 65535

    def connect(self):
        inserted_ip = self.ip_svar.get()
        if self.is_valid_ip(inserted_ip):
            server_ip = inserted_ip 
        else:
            messagebox.showwarning(
                "Invalid IP",
                f"The IP {inserted_ip} is not valid. "\
                "Please, try again with a valid IP."
            )
            self.logger.warning("The inserted IP is not valid.")
            return
        
        inserted_port = int(self.port_svar.get())
        if self.is_valid_port(inserted_port):
            server_port = inserted_port
        else:
            messagebox.showwarning(
                "Invalid Port",
                f"The port {inserted_port} is not valid. "\
                "Please, try again with a port between 1001 and 65534."
            )
            self.logger.warning("The inserted port is not valid.")
            return

        nickname = self.nickname_svar.get()
        if not nickname:
            messagebox.showwarning(
                "No Nickname",
                "Please, insert a nickname."
            )
            self.logger.warning("No nickname inserted.")
            return

        self.client = Client(
            nickname,
            self.nickname_color if self.nickname_color else "#000000",
            (server_ip, server_port),
            self.data_transferer,
            self.crypt,
            self.msg_guardian
        )
        self.chatbox_thread = Thread(
            target=self.write_to_chat_box,
            name="CHATBOX"
        )
        self.client.start()
        self.chatbox_thread.start()
        self.connected = True
        self.set_gui_state_to_connection_established()

    def disconnect(self):
        self.logger.debug("Disconnect request being processed...")
        self.client.message_output_q.put(QueueSignal._terminate_thread)
        self.logger.debug("Waiting for the client output queue to join...")
        self.client.message_output_q.join()
        self.logger.debug("Client output queue joined.")
        if self.chatbox_thread.is_alive():
            try:
                self.chatbox_thread.join()
            except RuntimeError:
                pass
        self.logger.debug("Chatbox thread terminated.")
        sleep(0.1)
        self.logger.debug("Disconnecting client...")
        self.client.disconnect_q.put(QueueSignal._disconnect)
        sleep(1)
        if not self.client.is_connected():
            self.logger.debug("Client disconnected.")
        else:
            self.logger.warn("Client still connected.")
        if self.client.is_alive():
            try:
                self.logger.debug("Joining client thread...")
                self.client.join()
                self.logger.debug("Client thread terminated.")
            except RuntimeError:
                pass
        self.logger.debug(f"Client alive? {self.client.is_alive()}")
        self.connected = False
        self.set_gui_state_to_disconnected()

    def stop(self):
        if messagebox.askokcancel("Quit?", "Do you want to exit the chat?"):
            if self.connected: self.disconnect()
            self.q_listener.stop()
            self.root.destroy()

    def gui_setup(self):
        self.root.protocol("WM_DELETE_WINDOW", self.stop)

        # Server data frame
        server_data_frame = ttk.Labelframe(self.root, text="Server Config")
        server_data_frame.grid(row=0, column=0)

        ip_label = ttk.Label(server_data_frame, text="IP: ")
        ip_label.grid(row=0, column=0, padx=0)
        self.ip_svar = StringVar()
        self.ip_entry = ttk.Entry(server_data_frame, textvariable=self.ip_svar, width=12)
        self.ip_entry.grid(row=0, column=1, ipadx=4, ipady=2)
        self.ip_entry.insert(0, SERVER_IP)

        port_label = ttk.Label(server_data_frame, text="Port no.: ")
        port_label.grid(row=1, column=0)
        self.port_svar = StringVar()
        self.port_entry = ttk.Entry(server_data_frame, textvariable=self.port_svar, width=12)
        self.port_entry.grid(row=1, column=1, ipadx=4, ipady=2)
        self.port_entry.insert(0, SERVER_PORT)

        nickname_label = ttk.Label(server_data_frame, text="Nickname: ")
        nickname_label.grid(row=2, column=0)
        self.nickname_svar = StringVar()
        self.nickname_entry = ttk.Entry(server_data_frame, textvariable=self.nickname_svar, width=12)
        self.nickname_entry.grid(row=2, column=1, ipadx=4, ipady=2)
        self.nickname_entry.insert(0, "test")

        color_label = ttk.Label(server_data_frame, text="Color: ")
        color_label.grid(row=3, column=0)
        self.color_btn = ttk.Button(server_data_frame, text="Choose color", command=self.choose_color, textvariable=self.nickname_color)
        self.color_btn.grid(row=3, column=1, ipadx=1, ipady=1)

        self.server_connect_btn = ttk.Button(server_data_frame, text="Connect", command=self.connect)
        self.server_connect_btn.grid(row=4, column=0, columnspan=1, ipadx=1)

        self.server_disconnect_btn = ttk.Button(server_data_frame, text="Disconnect", command=self.disconnect, state="disabled")
        self.server_disconnect_btn.grid(row=4, column=1, columnspan=1, ipadx=1)

        # Message box frame
        message_frame = ttk.Labelframe(self.root, text="Message box")
        message_frame.grid(row=4, column=0, columnspan=3, padx=10)

        self.message_box_text = Text(message_frame, height=2, width=70, state="disabled")
        self.message_box_text.grid(row=4, column=0, columnspan=3, pady=4)

        self.message_send_btn = ttk.Button(message_frame, text="Send", command=lambda: self.kbsend(1), state="disabled")
        self.message_send_btn.grid(row=5, column=0, columnspan=3, ipadx=4, ipady=2)

        # Chat box frame
        chat_frame = ttk.LabelFrame(self.root, text="Chat box")
        chat_frame.grid(row=0, column=2)

        self.chat_box_text = Text(chat_frame, height=17, width=50, state="disabled")
        self.chat_box_text.grid(row=0, column=2, columnspan=3)

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

    def run(self):
        self.setup_logger()
        self.q_listener.start()
        self.gui_setup()
        self.root.mainloop()


if __name__ == "__main__":
    gui_instance = ClientGui(
        data_transferer=TCPIPv4DataTransferer(),
        cryptographer=RSAFernetCryptographer(),
        msg_guardian=HMACMessageGuardian(DictBasedMessageFactory())
    )
    gui_instance.run()