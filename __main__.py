from server.server import Server

if __name__ == "__main__":
    server = Server("localhost", 8000)
    server.run()
