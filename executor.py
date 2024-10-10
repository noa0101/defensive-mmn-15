import sqlite3
import os
from datetime import datetime
import uuid
import encryption_utils
import shutil
from request_handler import Request_Parser
from response_handler import Response
import tempfile
from cksum import get_crc

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
            print("------------creating database-------------------")
            self.create_database()

        else:
            print("------------loading existing database-------------------")

    def create_database(self):
        connection = self.connect_to_db()
        cursor = connection.cursor()
        create_tables_command = """
            CREATE TABLE clients (
                ID BLOB PRIMARY KEY,
                Name CHAR(255),
                PublicKey CHAR(160),
                LastSeen DATETIME,
                AES_Key CHAR(256)
            );

            CREATE TABLE files (
                ID CHAR(16),
                FileName CHAR(255),
                PathName CHAR(255) PRIMARY KEY,
                Verified CHAR(1)
            );
            
            -- Indexes for performance optimization
            CREATE INDEX idx_client_name ON clients(Name);  -- Index on Name in clients
            CREATE INDEX idx_files_pathname ON files(PathName);  -- Index on PathName in files
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
            if request.code in Request_Parser.codes:
                print(f"Client made a request with code {request.code}: {Request_Parser.codes[request.code]}.")
            else:
                print(f"Client made a request with an invalid code: {request.code}.")
            print("--------------------------------------------------")

            func_name = self.FUNCTIONS_DICT.get(request.code)
            if not func_name:
                Response.send_general_error(request.sock)
            else:
                getattr(self, func_name)(request, cursor)

            self.update_last_seen(request.client_id, cursor)
            connection.commit()  # Commit changes

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            Response.send_general_error(request.sock)

        except Exception as e:
            print(f"Exception during server activity: {e}")
            Response.send_general_error(request.sock)

        finally:
            connection.close()
            print("--------------------------------------------------\n")


    @staticmethod
    def update_last_seen(client_id, cursor):
        if(Executor.client_exists(client_id, cursor)):
            current_time = datetime.now()
            cursor.execute("""UPDATE clients SET LastSeen = ? WHERE ID = ?""", (current_time, client_id))

    @staticmethod
    def client_exists(client_id, cursor):
        cursor.execute("SELECT 1 FROM clients WHERE ID = ?", (client_id,))
        result = cursor.fetchone()
        return result is not None

    @staticmethod
    def register(request, cursor):
        try:
            user_id = uuid.uuid4().bytes  # create new random user id
            cursor.execute(
                'INSERT INTO clients (ID, Name, PublicKey, AES_Key) VALUES (?, ?, ?, ?)',
                (user_id, request.body.name, None, None))
            resp = Response(DEFAULT_VERSION, Response.SUCCESSFUL_REGISTRATION, Response.Response_Body(user_id))
        except Exception as e:
            resp = Response(DEFAULT_VERSION, Response.REGISTRATION_FAILED, Response.Response_Body())
        resp.send_response(request.sock)

    @staticmethod
    def get_public_key(request, cursor):
        if not Executor.client_exists(request.client_id, cursor):
            raise Exception("Client does not exist in database.")

        aes_key = encryption_utils.generate_AES_key()
        public_key = request.body.public_key

        cursor.execute("""UPDATE clients SET PublicKey = ?, AES_Key = ? WHERE ID = ?""",
                       (public_key, aes_key, request.client_id))

        encrypted_aes_key = encryption_utils.RSA_encryption(aes_key, public_key)
        resp = Response(DEFAULT_VERSION, Response.PUBLIC_KEY_RECEIVED,
                        Response.Send_Key_Response_Body(request.client_id, encrypted_aes_key))
        resp.send_response(request.sock)

    @staticmethod
    def reconnect(request, cursor):
        if not Executor.client_exists(request.client_id, cursor):
            resp = Response(DEFAULT_VERSION, Response.RECONNECTION_FAILED, Response.Response_Body(request.client_id))

        else:
            cursor.execute("SELECT PublicKey FROM clients WHERE ID = ?", (request.client_id,))
            public_rsa_key = cursor.fetchone()[0]

            if public_rsa_key is None:
                resp = Response(DEFAULT_VERSION, Response.RECONNECTION_FAILED, Response.Response_Body(request.client_id))

            else:
                aes_key = encryption_utils.generate_AES_key()
                cursor.execute("""UPDATE clients SET AES_Key = ? WHERE ID = ?""", (aes_key, request.client_id))

                resp = Response(DEFAULT_VERSION, Response.SUCCESSFUL_RECONNECTION,
                            Response.Send_Key_Response_Body(request.client_id,
                                                             encryption_utils.RSA_encryption(aes_key, public_rsa_key)))
        resp.send_response(request.sock)

    @staticmethod
    def get_temp_file_path(id, filename):
        return os.path.join(tempfile.gettempdir(), "backup_server", id.hex(), filename)

    @staticmethod
    def get_file(request, cursor):
        if not Executor.client_exists(request.client_id, cursor):
            raise Exception("Client does not exist in database.")

        client_id = request.client_id
        filename = request.body.filename
        total_packs = request.body.total_packs
        org_file_size = request.body.orig_size

        cursor.execute("SELECT AES_Key FROM clients WHERE ID = ?", (client_id,))
        aes_key = cursor.fetchone()[0]
        if aes_key is None:
            Response.send_general_error(request.sock)
            return

        # create directory and get the file path
        temp_dir = os.path.join(tempfile.gettempdir(), "backup_server", client_id.hex())  # system's temp directory
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        temp_file = Executor.get_temp_file_path(client_id, filename)

        # if file with that path already exists, we will write over it (only the client can overwrite their own files)
        with open(temp_file, 'w') as file:
            for packet_num in range(total_packs):
                # check packet compatability
                if request.code != Request_Parser.SEND_FILE or request.body.filename != filename or request.body.total_packs != total_packs or request.body.orig_size != org_file_size or request.body.packet_num != packet_num+1:
                    print("Server expected to receive packet number", packet_num+1, "for file", filename, ". Received incompatible request.")
                    Response.send_general_error(request.sock)
                    return

                # decrypt message content and write it to file
                decrypted_content = encryption_utils.decrypt_aes(request.body.encrypted_content, aes_key)
                file.write(decrypted_content)

                # if expecting more packets of the file, read the next request
                if packet_num < total_packs-1:
                    request.read_request()

        # add file to files table (or replace an existing line with the new one)
        print("inserting into files table")
        cursor.execute(
            'INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)',
            (request.client_id, request.body.filename, str(temp_file), 0))

        # send appropriate response
        cksum, file_size = get_crc(temp_file)
        resp = Response(DEFAULT_VERSION, Response.FILE_RECEIVED,
                        Response.Send_File_Response_Body(request.client_id,
                                                         file_size, request.body.filename, cksum))
        resp.send_response(request.sock)

    @staticmethod
    def validate_crc(request, cursor):
        if not Executor.client_exists(request.client_id, cursor):
            raise Exception("Client does not exist in database.")

        cursor.execute("SELECT Verified FROM files WHERE FileName = ?", (request.body.name,))
        validated_row = cursor.fetchone()

        # the file is not found in the database
        if validated_row is None:
            raise Exception("File does not exist in database.")

        validated = validated_row[0]

        if validated == 1:  # if file has already been validated
            raise Exception("file has already been validated.")

        source_file = Executor.get_temp_file_path(request.client_id, request.body.name)
        destination_folder = os.path.join("c:\\backup_server", request.client_id.hex())

        # Ensure the destination directory exists
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)

        destination_file = os.path.join(destination_folder, request.body.name)
        shutil.move(source_file, destination_file)

        cursor.execute("DELETE FROM files WHERE PathName = ?", (source_file,))

        # allow writing over a previous file belonging to that client with the same name
        cursor.execute(
            'INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)',
            (request.client_id, request.body.name, str(destination_file), 1))

        resp = Response(DEFAULT_VERSION, Response.MESSAGE_RECEIVED, Response.Response_Body())
        resp.send_response(request.sock)

    @staticmethod
    def invalidate_crc(request, cursor):
        if not Executor.client_exists(request.client_id, cursor):
            raise Exception("Client does not exist in database.")
    @staticmethod
    def abort(request, cursor):
        if not Executor.client_exists(request.client_id, cursor):
            raise Exception("Client does not exist in database.")

        file_path = Executor.get_temp_file_path(request.client_id, request.body.name)
        if not os.path.exists(file_path):
            raise Exception("File does not exist in backup.")

        os.remove(file_path)
        cursor.execute("DELETE FROM files WHERE PathName = ?", (file_path,))
        resp = Response(DEFAULT_VERSION, Response.MESSAGE_RECEIVED, Response.Response_Body())
        resp.send_response(request.sock)
