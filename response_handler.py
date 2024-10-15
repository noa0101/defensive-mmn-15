'''
This file contains the Response class, that has methods to represent, serialize and send a response.
'''

import struct
DEFAULT_VERSION = 3

class Response:
    # response codes
    SUCCESSFUL_REGISTRATION = 1600
    REGISTRATION_FAILED = 1601
    PUBLIC_KEY_RECEIVED = 1602
    FILE_RECEIVED = 1603
    MESSAGE_RECEIVED = 1604
    SUCCESSFUL_RECONNECTION = 1605
    RECONNECTION_FAILED = 1606
    GENERAL_ISSUE = 1607
    codes = {
        1600: "SUCCESSFUL_REGISTRATION",
        1601: "REGISTRATION_FAILED",
        1602: "PUBLIC_KEY_RECEIVED",
        1603: "FILE_RECEIVED",
        1604: "MESSAGE_RECEIVED",
        1605: "SUCCESSFUL_RECONNECTION",
        1606: "RECONNECTION_FAILED",
        1607: "GENERAL_ISSUE"
    }

    def __init__(self, version, code, body):
        self.version = version
        self.code = code
        self.payload = body.serialize()
        self.payload_size = len(self.payload)

    def serialize(self):
        format_string = '<BHI'
        return struct.pack(format_string, self.version, self.code, self.payload_size) + self.payload

    def send_response(self, socket):
        print(f"Responding with code {self.code}: {self.codes[self.code]}.")
        socket.send(self.serialize())

    # classes to represent the different types of response bodies
    class Response_Body:
        def __init__(self, client_id=b''):  # default value for responses that don't contains a client id
            self.client_id = client_id

        def serialize(self):
            return self.client_id

    class Send_Key_Response_Body(Response_Body):
        def __init__(self, client_id, encrypted_key):
            super().__init__(client_id)
            self.encrypted_key = encrypted_key

        def serialize(self):
            return super().serialize()+self.encrypted_key

    class Send_File_Response_Body(Response_Body):
        def __init__(self, client_id, content_size, file_name, cksum):
            super().__init__(client_id)
            self.content_size = content_size
            self.file_name = file_name
            self.cksum = cksum

        def serialize(self):
            padded_file_name = self.file_name.encode('utf-8')[:255].ljust(255, b'\x00')
            format_string = '<I255sI'
            return super().serialize() + struct.pack(format_string, self.content_size, padded_file_name, self.cksum)

    # method to send a general error response
    @staticmethod
    def send_general_error(socket):
        resp = Response(DEFAULT_VERSION, Response.GENERAL_ISSUE, Response.Response_Body())
        resp.send_response(socket)
