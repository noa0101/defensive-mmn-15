import sqlite3
import os
from datetime import datetime
import uuid
import encryption_utils
import shutil
from request_handler import Request_Parser
from response_handler import Response
import tempfile

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
        self.db_file = 'defensive.db'
        first_run = not os.path.exists(self.db_file)

        if first_run:
            self.create_database()

    def create_database(self):
        connection = self.connect_to_db()
        cursor = connection.cursor()
        create_tables_command = """
            CREATE TABLE clients (
                ID CHAR(16),
                Name CHAR(255),
                PublicKey CHAR(160),
                LastSeen DATETIME,
                AES_Key CHAR(256)
            );

            CREATE TABLE files (
                ID CHAR(16),
                FileName CHAR(255),
                PathName CHAR(255),
                Verified CHAR(1)
            );
        """
        cursor.executescript(create_tables_command)
        connection.commit()
        connection.close()

    def connect_to_db(self):
        return sqlite3.connect(self.db_file)

    def execute(self, request):
        connection = self.connect_to_db()  # Create a new connection
        cursor = connection.cursor()

        try:
            func_name = self.FUNCTIONS_DICT.get(request.code)
            if func_name:
                getattr(self, func_name)(request, cursor)
            else:  # invalid code for request
                Response.send_general_error(request.sock)

            self.update_last_seen(request.client_id, cursor)
            connection.commit()  # Commit changes
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            # Handle error (e.g., send a response to the client)
        finally:
            connection.close()

    @staticmethod
    def update_last_seen(client_id, cursor):
        current_time = datetime.now()
        cursor.execute("""UPDATE clients SET LastSeen = ? WHERE ID = ?""", (current_time, client_id))

    @staticmethod
    def client_exists(name, cursor):
        cursor.execute("SELECT 1 FROM clients WHERE Name = ?", (name,))
        result = cursor.fetchone()
        return result is not None

    @staticmethod
    def register(request, cursor):
        if Executor.client_exists(request.body.username, cursor):
            Response.send_general_error(request.socket, Response.REGISTRATION_FAILED)
        else:  # if registered
            user_id = uuid.uuid4()  # create new random user id
            cursor.execute(
                'INSERT INTO clients (ID, Name, PublicKey, AES_Key) VALUES (?, ?, ?, ?)',
                (user_id, request.body.username, "", ""))
            resp = Response(DEFAULT_VERSION, Response.SUCCESSFUL_REGISTRATION, Response.Response_Body(user_id))
            resp.send_response(request.socket)

    @staticmethod
    def get_public_key(request, cursor):
        aes_key = encryption_utils.generate_AES_key()
        public_key = request.body.public_key

        cursor.execute("""UPDATE clients SET PublicKey = ?, AES_Key = ? WHERE ID = ?""",
                       (public_key, aes_key, request.client_id))

        encrypted_aes_key = encryption_utils.RSA_encryption(aes_key, public_key)
        resp = Response(DEFAULT_VERSION, Response.PUBLIC_KEY_RECEIVED,
                        Response.Send_Key_Response_Body(request.client_id, encrypted_aes_key))
        resp.send_response(request.socket)

    @staticmethod
    def reconnect(request, cursor):
        if not Executor.client_exists(request.body.username, cursor):
            resp = Response(DEFAULT_VERSION, Response.RECONNECTION_FAILED, Response.Response_Body(request.client_id))
        else:
            cursor.execute("SELECT PublicKey FROM clients WHERE ID = ?", (request.client_id,))
            public_rsa_key = cursor.fetchone()[0]
            aes_key = encryption_utils.generate_AES_key()
            cursor.execute("""UPDATE clients SET AES_Key = ? WHERE ID = ?""", (aes_key, request.client_id))

            resp = Response(DEFAULT_VERSION, Response.SUCCESSFUL_RECONNECTION,
                            Response.Send_Key_Response_Body(request.client_id,
                                                             encryption_utils.RSA_encryption(aes_key, public_rsa_key)))
        resp.send_response(request.socket)

    @staticmethod
    def get_file(request, cursor):
        # decrypt content
        cursor.execute("SELECT AES_Key FROM clients WHERE ID = ?", (request.client_id,))
        aes_key = cursor.fetchone()[0]
        decrypted_content = encryption_utils.decrypt_aes(request.body.encrypted_content, aes_key)

        # create file and write the content to it
        temp_dir = tempfile.gettempdir()  # system's temp directory
        temp_file = os.path.join(temp_dir, request.client_id, request.body.file_name)
        with open(temp_file, 'w') as temp_file:
            temp_file.write(decrypted_content)

        # add file to files table
        cursor.execute(
            'INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)',
            (request.client_id, request.body.file_name, os.path.join(temp_dir, request.body.file_name), 0))

        # send appropriate response
        cksum = encryption_utils.calc_crc(decrypted_content)
        resp = Response(DEFAULT_VERSION, Response.FILE_RECEIVED,
                        Response.Send_File_Response_Body(request.client_id,
                                                         len(decrypted_content), request.body.file_name, cksum))
        resp.send_response(request.socket)

    @staticmethod
    def validate_crc(request, cursor):
        cursor.execute("SELECT PathName FROM files WHERE FileName = ?", (request.body.file_name,))
        source_file = cursor.fetchone()[0]
        destination_folder = os.path.join("c:\\server_backup\\authenticated\\", request.client_id)

        # Ensure the destination directory exists
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)

        destination_file = os.path.join(destination_folder, request.body.file_name)
        shutil.move(source_file, destination_file)

        cursor.execute("""UPDATE files SET Verified = ?, PathName = ? WHERE PathName = ?""",
                       (1, destination_file, source_file))

    def invalidate_crc(self, request, cursor):
        pass  # no action needed here - everything stays as it is

    @staticmethod
    def abort(request, cursor):
        cursor.execute("SELECT PathName FROM files WHERE FileName = ?", (request.body.file_name,))
        file_path = cursor.fetchone()[0]
        os.remove(file_path)
        cursor.execute("DELETE FROM files WHERE PathName = ?", (file_path,))
