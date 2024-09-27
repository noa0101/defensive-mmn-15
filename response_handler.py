import struct
DEFAULT_VERSION = 3
class Response:
    SUCCESSFUL_REGISTRATION = 1600
    REGISTRATION_FAILED = 1601
    PUBLIC_KEY_RECEIVED = 1602
    FILE_RECEIVED = 1603
    MESSAGE_RECEIVED = 1604
    SUCCESSFUL_RECONNECTION = 1605
    RECONNECTION_FAILED = 1606
    GENERAL_ISSUE = 1607

    def __init__(self, version, code, body):
        self.version = version
        self.code = code
        self.payload = body.serialize()
        self.payload_size = len(self.payload)

    def serialize(self):
        format_string = '<BHI'
        return struct.pack(format_string, self.version, self.code, self.payload_size) + self.payload
    def send_response(self, socket):
        socket.send(self.serialize())
    class Response_Body:
        def __init__(self, client_id=''):
            self.client_id = client_id

        def serialize(self):
            return self.client_id.encode('utf-8')

    class Send_Key_Response_Body(Response_Body):
        def __init__(self, client_id, encrypted_key):
            super().__init__(client_id)
            self.encrypted_key = encrypted_key

        def serialize(self):
            return super().serialize()+self.encrypted_key.encode('utf-8')

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

    @staticmethod
    def send_general_error(socket):
        resp = Response(DEFAULT_VERSION, Response.GENERAL_ISSUE, Response.Response_Body())
        resp.send_response(socket)
