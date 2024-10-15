'''
This file contains the class that represents the server itself and the main function operating it.
'''

import os
import socket
import threading
from request_handler import Request_Parser
from executor import Executor


class Server:
    VERSION = 3
    DEFAULT_PORT = 1256

    # init connects the server to the port and initializes its executor object
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        port_num = self.DEFAULT_PORT
        if os.path.exists('port.info'):
            with open('port.info', 'r') as file:
                try:
                    port_num = int(file.read().strip())
                except ValueError:
                    pass  # if there was a problem reading the info file, the default port will be used

        self.sock.bind(('', port_num))
        print("Server listening on port", port_num)

        self.sock.listen()
        self.executor = Executor()  # initialize executor object for the server

    # accepts new clients on the port, each time a client connects opens a new thread to handle it
    def run(self):
        while True:
            conn, addr = self.sock.accept()
            # create a new thread for each client
            client_thread = threading.Thread(target=self.handle_client, args=(conn,))
            client_thread.start()

    # boolean function that checks whether a connection is still open
    @staticmethod
    def conn_open(conn):
        try:
            conn.send(b'')
            return True
        except ConnectionResetError:
            return False

    # function to handle a single client
    def handle_client(self, conn):
        print("New client connected!")
        request = Request_Parser(conn)

        try:
            while Server.conn_open(conn):
                request.read_request()  # read client's request from connection
                self.executor.execute(request)  # execute the request and respond appropriately

        except ConnectionError:  # there was a problem receiving or sending data from the connection, it was most likely closed by the client
            print('Client disconnected.')

        except Exception as e:  # may occur if an invalid request (that doesn't follow the protocol) was sent
            print("Exception in request handling.")

        finally:  # whether or not there has been an exception, close the connection and end this thread
            print('Closing connection.\n\n')
            conn.close()


# main "function" to set up the server
if __name__ == "__main__":
    try:
        server = Server()
        server.run()
    except Exception as e:
        print(f"Server program has ran into a problem: {e}")
