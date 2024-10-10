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


    @staticmethod
    def conn_open(conn):
        try:
            conn.send(b'')
            return True
        except ConnectionResetError:
            return False

    def handle_client(self, conn):
        print("New client connected!")
        request = Request_Parser(conn)

        try:
            while Server.conn_open(conn):
                request.read_request()
                self.executor.execute(request)

        except ConnectionError:
            print('Client disconnected.')

        except Exception as e:
            print("Exception in request handling.")

        finally:
            print('Closing connection.\n\n')
            conn.close()



if __name__ == "__main__":
    server = Server()
    server.run()
