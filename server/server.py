import socket
import threading
import uuid

from utils.models import User


class UserManager:
    def __init__(self):
        self.users = {}

    def add_user(self, client_socket: socket.socket, username: str, user_id: str) -> None:
        user = User(username=username, id=uuid.UUID(user_id))
        self.users[client_socket] = user
        print(f"User {user} connected.")

    def remove_user(self, client_socket: socket.socket) -> None:
        user = self.users.pop(client_socket)
        print(f"User {user} disconnected.")

    def get_user(self, client_socket: socket.socket) -> User:
        return self.users[client_socket]

    def get_socket_by_user_id(self, user_id: str) -> socket.socket | None:
        for s, u in self.users.items():
            if str(u.id) == user_id:
                return s
        return None


class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        self.user_manager = UserManager()

    def run(self) -> None:
        print(f"Server started on {self.host}:{self.port}")
        while True:
            client_socket, addr = self.server_socket.accept()
            client_socket.sendall("/user_id".encode())
            user_id = client_socket.recv(1024).decode()
            host, port = addr
            self.user_manager.add_user(client_socket, f"{host}:{port}", user_id)
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()
            for c_socket in self.user_manager.users:
                c_socket.sendall(f"users:{','.join(str(user) for user in self.user_manager.users.values())}".encode())

    def handle_client(self, client_socket: socket.socket) -> None:
        while True:
            try:
                data = client_socket.recv(2**16).decode()
                if not data:
                    break
                if data == "/exit":
                    break
                print(f"Received data from {self.user_manager.get_user(client_socket)}: {data}")
                user_id, message = data.split(":", maxsplit=1)
                receiver = self.user_manager.get_socket_by_user_id(user_id)
                if not receiver or receiver == client_socket:
                    continue
                print(receiver)
                receiver.sendall(f"message/{self.user_manager.get_user(client_socket)}/{message}".encode())
            except ConnectionResetError:
                break
        self.user_manager.remove_user(client_socket)
        client_socket.close()
