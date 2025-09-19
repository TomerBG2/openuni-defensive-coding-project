import socket
import threading
from server_model import ServerModel
from server_view import ServerView
from server_controller import ServerController

HOST = '0.0.0.0'


def main():
    model = ServerModel()
    view = ServerView()
    controller = ServerController(model, view)

    port = model.get_port_from_file()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, port))
        s.listen()
        view.log(f"Server listening on {HOST}:{port}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=controller.handle_client,
                             args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
