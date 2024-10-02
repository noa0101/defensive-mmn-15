#include "client.h"

template <typename T>
void Request::add_int_serialization(std::string serialization, T num, uint64_t& offset) {
    T num_le = boost::endian::native_to_little(num);
    std::memcpy(serialization.data() + offset, &num_le, sizeof(num_le));
    offset += sizeof(num_le);
}

std::string Request::Request_Header::serialize() {
    std::string serialized_head(sizeof(client_id) + sizeof(version) + sizeof(code) + sizeof(payload_size), '\0');
    uint64_t offset = 0;

    std::memcpy(serialized_head.data() + offset, client_id, sizeof(client_id));
    offset += sizeof(client_id);

    add_int_serialization<uint8_t>(serialized_head, version, offset);
    add_int_serialization<uint8_t>(serialized_head, code, offset);
    add_int_serialization<uint8_t>(serialized_head, payload_size, offset);
    
    return serialized_head;
}

Request::Request_Header::Request_Header(unsigned char* id, uint8_t ver, uint16_t request_code, uint32_t size) {
    std::copy(id, id + CLIENT_ID_SIZE, client_id);
    version = ver;
    code = request_code;
    payload_size = size;
}

Request::Send_Key_Request_Body::Send_Key_Request_Body(std::string name, std::string key) : Request_Body(name), public_key(key) {}


std::string Request::Send_File_Request_Body::serialize_short_fields() {
    std::string serialized_data(sizeof(content_size) + sizeof(orig_size) + sizeof(packet_number) + sizeof(total_packets) + NAME_LEN, '\0');
    uint64_t offset = 0;

    add_int_serialization<uint32_t>(serialized_data, content_size, offset);
    add_int_serialization<uint32_t>(serialized_data, orig_size, offset);
    add_int_serialization<uint16_t>(serialized_data, packet_number, offset);
    add_int_serialization<uint16_t>(serialized_data, total_packets, offset);

    std::memcpy(serialized_data.data() + offset, &name, name.size());

    return serialized_data;
}


Request::Request(Request_Header head, Request_Body body) :
    head(head), body(body) {}


void Request::check_name_len(std::string file_name) {
    if (file_name.size() > NAME_LEN)
        throw std::runtime_error("Given name is too long, request cannot be generated!");
}

void Request::send_request(std::shared_ptr<tcp::socket>& socket) {
    boost::asio::write(*socket, boost::asio::buffer(head.serialize()));
    body.send_request_body(socket);
}

void Request::general_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, std::string& name) {
    Request::check_name_len(name);
    Request_Body bod(name);
    Request req(Request_Header(id, ver, code, bod.get_len()), bod);
    req.send_request(socket);
}

void Request::send_key_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, std::string &name, std::string &key) {
    Request::check_name_len(name);
    if (key.size() != PUBLIC_KEY_SIZE)
        throw std::runtime_error("Public key should be of length " + std::to_string(PUBLIC_KEY_SIZE));
    
    Send_Key_Request_Body bod(name, key);
    Request req(Request_Header(id, ver, code, bod.get_len()), bod);
    req.send_request(socket);
}

Request::Send_File_Request_Body::Send_File_Request_Body(uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string &file_name, char * content) :
    content_size(content_s), orig_size(orig_s), packet_number(pack_num),
    total_packets(tot_packs), Request_Body(file_name), message_content(content) {}

void Request::send_file_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string& file_name, char * content) {
    Request::check_name_len(file_name);
    Request::Send_File_Request_Body bod(content_s, orig_s, pack_num, tot_packs, file_name, content);
    Request req(Request_Header(id, ver, code, bod.get_len()), bod);
    req.send_request(socket);
}

Request::Request_Body::Request_Body(std::string name) : name(name) {}

uint32_t Request::Request_Body::get_len() {
    return NAME_LEN;
}

uint32_t Request::Send_Key_Request_Body::get_len() {
    return NAME_LEN + PUBLIC_KEY_SIZE;
}

uint32_t Request::Send_File_Request_Body::get_len() {
    return sizeof(content_size) + sizeof(orig_size) + sizeof(packet_number) + sizeof(total_packets) + NAME_LEN + content_size;
}

void Request::Request_Body::send_request_body(std::shared_ptr<tcp::socket>& socket) {
    boost::asio::write(*socket, boost::asio::buffer(name));
}

void Request::Send_Key_Request_Body::send_request_body(std::shared_ptr<tcp::socket>& socket) {
    boost::asio::write(*socket, boost::asio::buffer(name + public_key));
}

void Request::Send_File_Request_Body::send_request_body(std::shared_ptr<tcp::socket>& socket) {
    boost::asio::write(*socket, boost::asio::buffer(serialize_short_fields()));
    boost::asio::write(*socket, boost::asio::buffer(message_content, content_size));
}