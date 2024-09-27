import sqlite3
from request_handler import Request_Parser
from response_handler import Response
import os


class Executor:
    CLIENT_ID_SIZE = 16
    NAME_LEN = 255
    PUBLIC_KEY_SIZE = 160
    AES_KEY_SIZE = 256

    FUNCTIONS_DICT = {
        Request_Parser.REGISTRATION: "register",
        Request_Parser.SEND_PUBLIC_KEY: "get_public_key",
        Request_Parser.RECONNECTION: "reconnect",
        Request_Parser.SEND_FILE: "get_file",
        Request_Parser.VALID_CRC: "validate_crc",
        Request_Parser.INVALID_CRC: "invalidate_crc",
        Request_Parser.FOURTH_INVALID_CRC: "abort"
    }

    def __init__(self):
        first_run = not os.path.exists('defensive.db')
        self.sqlite_connection = sqlite3.connect('defensive.db')
        self.cursor = self.sqlite_connection.cursor()

        if first_run:
            create_tables_command = f"""
                    CREATE TABLE clients ( 
                    ID CHAR({Executor.CLIENT_ID_SIZE}), 
                    Name CHAR({Executor.NAME_LEN}), 
                    PublicKey CHAR({Executor.PUBLIC_KEY_SIZE}), 
                    LastSeen DATETIME, 
                    AES_Key CHAR({Executor.AES_KEY_SIZE}));

                CREATE TABLE files ( 
                    ID CHAR({Executor.CLIENT_ID_SIZE}), 
                    FileName CHAR({Executor.NAME_LEN}), 
                    PathName CHAR({Executor.NAME_LEN}), 
                    Verified CHAR(1));
            """

            # Use executescript() to execute multiple commands
            self.cursor.executescript(create_tables_command)

            # Commit the changes
            self.sqlite_connection.commit()

    def execute(self, request):
        func_name = self.FUNCTIONS_DICT.get(request.code)
        if func_name:
            getattr(self, func_name)(request)
        else:  # invalid code for request
            Response.send_general_error(request.sock)

    def __del__(self):
        self.sqlite_connection.close()