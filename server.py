import socket
import struct
import selectors
from request_handler import Request_Parser
from executor import Executor


class Server:
    DEFAULT_VERSION = 3

    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.sock = socket.socket()
        self.sock.bind(('localhost', 1234))
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