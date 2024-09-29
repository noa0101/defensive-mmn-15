import os
import socket
import struct
import selectors
from request_handler import Request_Parser
from executor import Executor


class Server:
    DEFAULT_VERSION = 3
    DEFAULT_PORT = 1256
    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.sock = socket.socket()

        port_num = self.DEFAULT_PORT
        if os.path.exists('port.info'):
            with open('port.info', 'r') as file:
                try:
                    port_num = int(file.read().strip())
                except ValueError:
                    pass
        self.sock.bind(('', port_num))
        print("server listening on port", port_num)

        self.sock.listen(100)
        self.sock.setblocking(False)
        self.sel.register(self.sock, selectors.EVENT_READ, self.accept)
        self.executor = Executor()

    def run(self):
        while True:
            events = self.sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj)

    def accept(self):
        conn, addr = self.sock.accept()  # Should be ready
        print('accepted', conn, 'from', addr)
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.handle_client)

    def handle_client(self, conn):
        request = Request_Parser(conn)
        try:
            while request.read_request():  # while the client keeps sending requests
                self.executor.execute(request)

        except ConnectionResetError:
            # Handle client disconnecting abruptly
            print('Client disconnected abruptly')
            self.sel.unregister(conn)
            conn.close()


if __name__ == "__main__":
    server = Server()
    server.run()