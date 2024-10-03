import os
import socket
import threading
from request_handler import Request_Parser
from executor import Executor


class Server:
    DEFAULT_VERSION = 3
    DEFAULT_PORT = 1256

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        port_num = self.DEFAULT_PORT
        if os.path.exists('port.info'):
            with open('port.info', 'r') as file:
                try:
                    port_num = int(file.read().strip())
                except ValueError:
                    pass

        self.sock.bind(('', port_num))
        print("Server listening on port", port_num)

        self.sock.listen(100)
        self.executor = Executor()

    def run(self):
        while True:
            conn, addr = self.sock.accept()
            # create a new thread for each client
            client_thread = threading.Thread(target=self.handle_client, args=(conn,))
            client_thread.start()

    def handle_client(self, conn):
        print("New client connected!")
        try:
            request = Request_Parser(conn)
            while request.read_request():
                self.executor.execute(request)
            Server.close_connection(conn)

        except ConnectionResetError:
            print('Client disconnected abruptly')
            Server.close_connection(conn)

    @staticmethod
    def close_connection(conn):
        print('Closing connection')
        conn.close()


if __name__ == "__main__":
    server = Server()
    server.run()
