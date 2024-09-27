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
        self.client_id = self.sock.revc(Request_Parser.CLIENT_ID_SIZE)
        if self.client_id == '': # No message from client
            return False
        self.version, self.code, self.payload_size = (
            struct.unpack('<BHI',
                          self.sock.recv(Request_Parser.VERSION_SIZE + Request_Parser.CODE_SIZE + Request_Parser.PAYLOAD_SIZE_SIZE)))
        self.payload = self.sock.recv(self.payload_size)
        self.parse_payload(self.payload)
        return True

    def parse_payload(self, payload):
        if self.code == self.SEND_FILE:
            self.Send_File_Request_Body(payload)
        self.filename = payload[0:Request_Parser.NAME_LEN].decode('utf-8')
        if self.code == Request_Parser.SEND_PUBLIC_KEY:
            self.public_key = payload[Request_Parser.NAME_LEN:Request_Parser.PUBLIC_KEY_SIZE]

    class Send_File_Request_Body:
        S_CONTENT_SIZE = 4
        S_ORIG_SIZE = 4
        S_PACKET_NUM = 2
        S_TOTAL_PACKS = 2

        def __init__(self, data):
            num_fields_size = self.S_ORIG_SIZE + self.S_CONTENT_SIZE + self.S_PACKET_NUM + self.S_TOTAL_PACKS
            self.content_size, self.orig_size, self.packet_num, self.total_packs = struct.unpack('<IIHH', data[
                                                                                                          0:num_fields_size])
            self.filename = data[num_fields_size:num_fields_size + Request_Parser.NAME_LEN].decode('utf-8')
            self.content = data[
                           num_fields_size + Request_Parser.NAME_LEN:num_fields_size + Request_Parser.NAME_LEN + self.content_size].decode(
                'utf-8')
