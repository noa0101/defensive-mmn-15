import struct
import socket


class Request_Parser:
    REGISTRATION = 825
    SEND_PUBLIC_KEY = 826
    RECONNECTION = 827
    SEND_FILE = 828
    VALID_CRC = 900
    INVALID_CRC = 901
    FOURTH_INVALID_CRC = 902

    CLIENT_ID_SIZE = 16
    NAME_LEN = 255
    PUBLIC_KEY_SIZE = 160

    VERSION_SIZE = 1
    CODE_SIZE = 2
    PAYLOAD_SIZE_SIZE = 4

    def __init__(self, socket):
        self.sock = socket

    # returns False if no text was received from the client - the connection was closed. True otherwise
    def read_request(self):
        '''
        data = self.sock.recv(1024)
        print(data)
        print('len:', len(data))
        '''
        self.client_id = self.sock.recv(Request_Parser.CLIENT_ID_SIZE)
        if self.client_id == '':  # No message from client
            return False
        self.version, self.code, self.payload_size = (
            struct.unpack('<BHI',
                          self.sock.recv(Request_Parser.VERSION_SIZE + Request_Parser.CODE_SIZE + Request_Parser.PAYLOAD_SIZE_SIZE)))
        self.payload = self.sock.recv(self.payload_size)
        self.parse_payload(self.payload)
        return True

    def parse_payload(self, payload):
        if self.code == self.SEND_FILE:
            self.body = Request_Parser.Send_File_Request_Body(payload)
        elif self.code == Request_Parser.SEND_PUBLIC_KEY:
            self.body = Request_Parser.Send_Key_Request_Body(payload)
        else:
            self.body = Request_Parser.General_Request_body(payload)


    class General_Request_body:
        def __init__(self, data):
            self.name = data[0:Request_Parser.NAME_LEN].decode('utf-8')
    class Send_Key_Request_Body:
        def __init__(self, data):
            self.name = data[0:Request_Parser.NAME_LEN].decode('utf-8')
            self.public_key = data[Request_Parser.NAME_LEN:Request_Parser.PUBLIC_KEY_SIZE].decode('utf-8')

    class Send_File_Request_Body:
        S_CONTENT_SIZE = 4
        S_ORIG_SIZE = 4
        S_PACKET_NUM = 2
        S_TOTAL_PACKS = 2

        def __init__(self, data):
            num_fields_size = self.S_ORIG_SIZE + self.S_CONTENT_SIZE + self.S_PACKET_NUM + self.S_TOTAL_PACKS
            self.content_size, self.orig_size, self.packet_num, self.total_packs = struct.unpack('<IIHH', data[0:num_fields_size])
            self.filename = data[num_fields_size:num_fields_size + Request_Parser.NAME_LEN].decode('utf-8')
            self.encrypted_content = data[num_fields_size + Request_Parser.NAME_LEN:num_fields_size + Request_Parser.NAME_LEN + self.content_size].decode('utf-8')
