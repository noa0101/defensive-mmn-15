import struct
import socket
import uuid



class Request_Parser:
    REGISTRATION = 825
    SEND_PUBLIC_KEY = 826
    RECONNECTION = 827
    SEND_FILE = 828
    VALID_CRC = 900
    INVALID_CRC = 901
    FOURTH_INVALID_CRC = 902

    codes = {
        825: "REGISTRATION",
        826: "SEND_PUBLIC_KEY",
        827: "RECONNECTION",
        828: "SEND_FILE",
        900: "VALID_CRC",
        901: "INVALID_CRC",
        902: "FOURTH_INVALID_CRC"
    }

    CLIENT_ID_SIZE = 16
    NAME_LEN = 255
    PUBLIC_KEY_SIZE = 160

    VERSION_SIZE = 1
    CODE_SIZE = 2
    PAYLOAD_SIZE_SIZE = 4

    def __init__(self, socket):
        self.sock = socket

    def recv_exact(self, num_bytes):
        """Receive exactly `num_bytes` from the socket."""
        data = b''
        while len(data) < num_bytes:
            packet = self.sock.recv(num_bytes - len(data))
            if not packet:
                raise ConnectionError("Connection closed unexpectedly.")
            data += packet
        return data

    # returns False if no text was received from the client - the connection was closed. True otherwise
    def read_request(self):
        self.client_id = self.recv_exact(Request_Parser.CLIENT_ID_SIZE)
        self.version, self.code, self.payload_size = (
            struct.unpack('<BHI',
                          self.recv_exact(Request_Parser.VERSION_SIZE + Request_Parser.CODE_SIZE +
                                         Request_Parser.PAYLOAD_SIZE_SIZE)))

        if self.code in Request_Parser.codes:
            print(f"Client made a request with code {self.code}: {Request_Parser.codes[self.code]}.")
        else:
            print(f"Client made a request with an invalid code: {self.code}.")


        self.payload = self.recv_exact(self.payload_size)
        self.parse_payload(self.payload)

    def parse_payload(self, payload):
        if self.code == self.SEND_FILE:
            self.body = Request_Parser.Send_File_Request_Body(payload)
        elif self.code == Request_Parser.SEND_PUBLIC_KEY:
            self.body = Request_Parser.Send_Key_Request_Body(payload)
        else:
            self.body = Request_Parser.General_Request_body(payload)


    class General_Request_body:
        def __init__(self, data):
            self.name = data[0:Request_Parser.NAME_LEN].decode('utf-8').rstrip('\x00')
    class Send_Key_Request_Body:
        def __init__(self, data):
            self.name = data[0:Request_Parser.NAME_LEN].decode('utf-8').rstrip('\x00')
            self.public_key = data[Request_Parser.NAME_LEN:Request_Parser.NAME_LEN+Request_Parser.PUBLIC_KEY_SIZE]

    class Send_File_Request_Body:
        S_CONTENT_SIZE = 4
        S_ORIG_SIZE = 4
        S_PACKET_NUM = 2
        S_TOTAL_PACKS = 2

        def __init__(self, data):
            num_fields_size = self.S_ORIG_SIZE + self.S_CONTENT_SIZE + self.S_PACKET_NUM + self.S_TOTAL_PACKS
            self.content_size, self.orig_size, self.packet_num, self.total_packs = struct.unpack('<IIHH', data[0:num_fields_size])
            self.filename = data[num_fields_size:num_fields_size + Request_Parser.NAME_LEN].decode('utf-8').rstrip('\x00')
            self.encrypted_content = data[num_fields_size + Request_Parser.NAME_LEN:num_fields_size + Request_Parser.NAME_LEN + self.content_size]
