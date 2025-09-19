import threading
import time

DEFAULT_PORT = 1357


class Client:
    def __init__(self, client_id: bytes, username: str, public_key: bytes):
        self.client_id = client_id  # 16 bytes
        self.username = username
        self.public_key = public_key  # 160 bytes
        self.last_seen = time.time()


class Message:
    def __init__(self, msg_id: int, to_client: bytes, from_client: bytes, msg_type: int, content: bytes):
        self.msg_id = msg_id
        self.to_client = to_client
        self.from_client = from_client
        self.msg_type = msg_type
        self.content = content


class ServerModel:
    def __init__(self):
        self.clients = {}  # client_id (bytes) -> Client
        self.messages = []
        self.lock = threading.Lock()
        self.next_msg_id = 1

    def register_client(self, client: Client):
        with self.lock:
            self.clients[client.client_id] = client

    def get_client(self, client_id: bytes):
        with self.lock:
            return self.clients.get(client_id)

    def all_clients(self):
        with self.lock:
            return list(self.clients.values())

    def add_message(self, msg: Message):
        with self.lock:
            msg.msg_id = self.next_msg_id
            self.next_msg_id += 1
            self.messages.append(msg)

    def get_messages_for(self, client_id: bytes):
        with self.lock:
            msgs_clone = [
                m for m in self.messages if m.to_client == client_id]
            for m in msgs_clone:
                self.messages.remove(m)
            return msgs_clone

    @staticmethod
    def get_port_from_file():
        try:
            with open("myport.info") as f:
                port_str = f.read().strip()
                port = int(port_str)
                if 1024 <= port <= 65535:
                    return port
                else:
                    print(
                        f"Port number {port} in myport.info is out of valid range (1024-65535). Using default port {DEFAULT_PORT}.")
                    return DEFAULT_PORT
        except Exception as e:
            print(
                f"Error reading port from myport.info: {e}. Using default port {DEFAULT_PORT}.")
            return DEFAULT_PORT
