#include "client.h"

std::string Request::serialize() {
    return head.serialize() + payload;
}


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

Request::Request_Header::Request_Header(unsigned char* id, uint8_t ver, uint16_t request_code, uint64_t size) {
    std::copy(id, id + CLIENT_ID_SIZE, client_id);
    version = ver;
    code = request_code;
    payload_size = size;
}

std::string Request::Send_File_Request_Body::serialize() {
    std::string serialized_data(sizeof(content_size) + sizeof(orig_size) + sizeof(packet_number) + sizeof(total_packets) + NAME_LEN + content_size, '\0');
    uint64_t offset = 0;

    add_int_serialization<uint32_t>(serialized_data, content_size, offset);
    add_int_serialization<uint32_t>(serialized_data, orig_size, offset);
    add_int_serialization<uint16_t>(serialized_data, packet_number, offset);
    add_int_serialization<uint16_t>(serialized_data, total_packets, offset);

    std::memcpy(serialized_data.data() + offset, &file_name, file_name.size());
    offset += sizeof(NAME_LEN);

    std::memcpy(serialized_data.data() + offset, &message_content, content_size);
}


Request::Request(unsigned char id[], uint8_t ver, uint16_t code, std::string payload) :
    head(id, ver, code, payload.size()), payload(payload) {}


void Request::check_name_len(std::string file_name) {
    if (file_name.size() > NAME_LEN)
        throw std::runtime_error("Given name is too long, request cannot be generated!");
}

Request Request::generate_general_request(unsigned char id[], uint8_t ver, uint16_t code, std::string name) {
    Request::check_name_len(name);
    return Request(id, ver, code, name);
}

Request Request::generate_send_key_request(unsigned char id[], uint8_t ver, uint16_t code, std::string name, std::string key) {
    Request::check_name_len(name);
    if (key.size() != PUBLIC_KEY_SIZE)
        throw std::runtime_error("Public key should be of length " + std::to_string(PUBLIC_KEY_SIZE));
    
    return Request(id, ver, code, name + key);
}

Request::Send_File_Request_Body::Send_File_Request_Body(uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string file_name, std::string* content) :
    content_size(content_s), orig_size(orig_s), packet_number(pack_num),
    total_packets(tot_packs), file_name(file_name), message_content(content) {}

Request Request::generate_send_file_request(unsigned char id[], uint8_t ver, uint16_t code, uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string file_name, std::string *content) {
    Request::check_name_len(file_name);
    Request::Send_File_Request_Body body(content_s, orig_s, pack_num, tot_packs, file_name, content);
    std::string payload = body.serialize();
    return Request(id, ver, code, payload);
}