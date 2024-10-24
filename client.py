import socket
import threading
from ast import literal_eval

from utils.manager import get_encryption_algorithm, get_signature_algorithm
from utils.models import User


class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.receivers: list[User] = []
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        host, port = self.client_socket.getsockname()
        self.user = User(username=f"{host}:{port}")

    def run(self) -> None:
        print(f"Client started on {self.client_socket.getsockname()}")
        threading.Thread(target=self.send_data).start()
        threading.Thread(target=self.receive_data).start()

    def send_data(self) -> None:
        while True:
            data = input()
            if data == "/exit":
                self.client_socket.sendall(data.encode())
                break
            for receiver in self.receivers:
                if str(receiver.id) == str(self.user.id):
                    continue
                encryption = get_encryption_algorithm(receiver)
                encrypted_data = encryption.encrypt(data.encode())
                signer = get_signature_algorithm(self.user)
                signature = signer.sign(encrypted_data)
                self.client_socket.sendall(f"{receiver.id}:{encrypted_data}signature:{signature}".encode())

    def receive_data(self) -> None:
        while True:
            data = self.client_socket.recv(2**16).decode()
            if data.startswith("users:"):
                users = data.split("users:")[1].split(",")
                for user in users:
                    username, user_id = user.split()
                    self.receivers.append(User(username=username, id=user_id))
                print(f"Receiver List Updated: {self.receivers}")
                continue
            if data.startswith("message/"):
                _, sender, message = data.split("/", 2)
                sign = literal_eval(message.split("signature:")[1])
                sender_name, sender_id = sender.split()
                sender = User(username=sender_name, id=sender_id)
                verifier = get_signature_algorithm(sender)
                message = literal_eval(message.split("signature:")[0])
                encryption = get_encryption_algorithm(self.user)
                decrypted_data = encryption.decrypt(message)
                print(f"{sender}: {decrypted_data} ({message}) | Verified: {verifier.verify(message, sign)}")
                continue
            if data.startswith("/user_id"):
                self.client_socket.sendall(str(self.user.id).encode())
                continue
            print(data)


if __name__ == "__main__":
    client = Client("localhost", 8000)
    client.run()
