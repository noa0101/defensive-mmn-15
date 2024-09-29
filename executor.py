import sqlite3
from request_handler import Request_Parser
from response_handler import Response
import os
from datetime import datetime
import uuid
import encryption_utils
import shutil


DEFAULT_VERSION = 3

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
            self.sqlite_connection.commit()

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
        self.update_last_seen(request.file_id)
        self.sqlite_connection.commit()

    def update_last_seen(self, client_id):
        current_time = datetime.now()  # save current date and time
        self.cursor.execute("""UPDATE clients 
                                          SET LastSeen = ?
                                          WHERE ID = ?""",
                            (client_id, current_time))

    def client_exists(self, name):
        self.cursor.execute("SELECT 1 FROM clients WHERE Name = ?", (name,))
        result = self.cursor.fetchone()
        return result is not None

    def register(self, request):
        if self.client_exists(request.body.username):
            Response.send_general_error(request.socket, Response.REGISTRATION_FAILED)

        else:  # if registered
            user_id = uuid.uuid4()  # create new random user id
            self.cursor.execute(
                'INSERT INTO clients (ID, Name, PublicKey, AES_Key) VALUES (?, ?, ?, ?, ?)',
                (user_id, request.body.username, "", ""))
            resp = Response(DEFAULT_VERSION, Response.SUCCESSFUL_REGISTRATION, Response.Response_Body(user_id))
            resp.send_response(request.socket)

    def get_public_key(self, request):
        aes_key = encryption_utils.generate_AES_key()
        public_key = request.body.public_key

        self.cursor.execute("""UPDATE clients 
                          SET PublicKey = ?, AES_Key = ?
                          WHERE ID = ?""",
                            (request.client_ID, public_key, aes_key))

        encrypted_aes_key = encryption_utils.RSA_encryption(aes_key, public_key)
        resp = Response(DEFAULT_VERSION, Response.PUBLIC_KEY_RECEIVED,
                        Response.Send_Key_Response_Body(request.client_ID, encrypted_aes_key))
        resp.send_response(request.socket)

    def reconnect(self, request):
        valid_reconnection = True
        if not self.client_exists(request.body.username):
            valid_reconnection = False
        else:
            self.cursor.execute("SELECT AES_Key FROM clients WHERE ID = ?", (request.client_id,))
            aes_key = self.cursor.fetchall()
            if(aes_key is None):
                valid_reconnection = False
        if valid_reconnection:
            self.cursor.execute("SELECT PublicKey FROM clients WHERE ID = ?", (request.client_id,))
            public_rsa_key = self.cursor.fetchall()
            resp = Response(DEFAULT_VERSION, Response.SUCCESSFUL_RECONNECTION, Response.Send_Key_Response_Body
            (request.client_id, encryption_utils.RSA_encryption(aes_key, public_rsa_key)))
        else:
            resp = Response(DEFAULT_VERSION, Response.RECONNECTION_FAILED, Response.Response_Body(request.client_id))
        resp.send_response(request.socket)

    def get_file(self, request):
        self.cursor.execute("SELECT AES_Key FROM clients WHERE ID = ?", (request.client_id,))
        aes_key = self.cursor.fetchall()

        decrypted_content = encryption_utils.decrypt_aes(request.body.ecrypted_content, aes_key)
        directory = os.path.join("c:\\server_backup\\unauthenticated\\", request.client_id)
        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(os.path.join(directory, request.body.file_name), 'w') as file:
            file.write(decrypted_content)

        cksum = encryption_utils.calc_crc(decrypted_content)

        self.cursor.execute(
            'INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?, ?)',
            (request.client_id, request.body.file_name, directory+request.body.file_name, 0))

        resp = Response(DEFAULT_VERSION, Response.FILE_RECEIVED,
                        Response.Send_File_Response_Body(request.client_id,
                                                         len(decrypted_content), request.body.file_name, cksum))
        resp.send_response(request.socket)

    def validate_crc(self, request):
        self.cursor.execute("SELECT PathName FROM files WHERE FileName = ?", (request.body.file_name,))
        source_file = self.cursor.fetchall()
        destination_folder = os.path.join("c:\\server_backup\\authenticated\\", request.client_id)

        # Ensure the destination directory exists
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)

        destination_file = os.path.join(destination_folder, request.body.file_name)
        shutil.move(source_file, destination_file)

        self.cursor.execute("""UPDATE files 
                                  SET Verified = ?, PathName = ?
                                  WHERE PathName = ?""",
                            (1, destination_file, source_file))

    def invalidate_crc(self, request):
        pass

    def abort(self, request):
        self.cursor.execute("SELECT PathName FROM files WHERE FileName = ?", (request.body.file_name,))
        file_path = self.cursor.fetchall()
        os.remove(file_path)
        self.cursor.execute("DELETE FROM files WHERE PathName = ?", (file_path,))

    def __del__(self):
        self.sqlite_connection.close()
