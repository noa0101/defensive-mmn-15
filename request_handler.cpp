#include "client.h"
/*
* This file contains code that handles the requests according to the protocol.
*/


/* request class methods */
//constructor
Request::Request(std::shared_ptr<Request_Header> head, std::shared_ptr<Request_Body> body)
    : head(head), body(body) {}

//function to send request to the server
void Request::send_request(std::shared_ptr<tcp::socket>& socket) {
    boost::asio::write(*socket, boost::asio::buffer(head->serialize()));
    body->send_request_body(socket);
}

//method to read a number of type T from message, pushes offset by the amount of bytes read and returns the read value
template <typename T>
void Request::add_int_serialization(std::string& serialization, T num, uint64_t& offset) {
    T num_le = boost::endian::native_to_little(num);
    std::memcpy(serialization.data() + offset, &num_le, sizeof(num_le));
    offset += sizeof(num_le);
}

//function to ure the given name is not too long  for the protocol
void Request::check_name_len(std::string& file_name) {
    if (file_name.size() >= NAME_LEN) //cannot be 255, as room m ust be left for the null terminator
        throw std::runtime_error("Given name is too long, request cannot be generated!");
}


/* request header methods */
Request::Request_Header::Request_Header(unsigned char* id, uint8_t ver, uint16_t request_code, uint32_t size) {
    std::copy(id, id + CLIENT_ID_SIZE, client_id);
    version = ver;
    code = request_code;
    payload_size = size;
}

std::string Request::Request_Header::serialize() {
    std::string serialized_head(CLIENT_ID_SIZE + sizeof(version) + sizeof(code) + sizeof(payload_size), '\0');
    uint64_t offset = 0;

    std::memcpy(serialized_head.data() + offset, client_id, CLIENT_ID_SIZE);
    offset += CLIENT_ID_SIZE;
    add_int_serialization<uint8_t>(serialized_head, version, offset);
    add_int_serialization<uint16_t>(serialized_head, code, offset);
    add_int_serialization<uint32_t>(serialized_head, payload_size, offset);

    return serialized_head;
}




/* virtual functions for the different kinds of request bodies(all inherit from Request_Body) */

//constructors
Request::Request_Body::Request_Body(std::string name) : name(name) {}

Request::Send_Key_Request_Body::Send_Key_Request_Body(std::string& name, std::string& key) : Request_Body(name), public_key(key) {}

Request::Send_File_Request_Body::Send_File_Request_Body(uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string& file_name, std::shared_ptr<std::string> &content) :
    content_size(content_s), orig_size(orig_s), packet_number(pack_num),
    total_packets(tot_packs), Request_Body(file_name), message_content(content) {}



//get the length of the serialization of the message body
uint32_t Request::Request_Body::get_len() {
    return NAME_LEN;
}

uint32_t Request::Send_Key_Request_Body::get_len() {
    return NAME_LEN + PUBLIC_KEY_SIZE;
}

uint32_t Request::Send_File_Request_Body::get_len() {
    return sizeof(content_size) + sizeof(orig_size) + sizeof(packet_number) + sizeof(total_packets) + NAME_LEN + content_size;
}


//sends the serialization of the request body to the socket
void Request::Request_Body::send_request_body(std::shared_ptr<tcp::socket>& socket) {
    std::string padding(NAME_LEN - name.size(), '\0');
    boost::asio::write(*socket, boost::asio::buffer(name+padding));
}

void Request::Send_Key_Request_Body::send_request_body(std::shared_ptr<tcp::socket>& socket) {
    std::string padding(NAME_LEN - name.size(), '\0');
    boost::asio::write(*socket, boost::asio::buffer(name + padding + public_key));
}

void Request::Send_File_Request_Body::send_request_body(std::shared_ptr<tcp::socket>& socket) {
    boost::asio::write(*socket, boost::asio::buffer(serialize_short_fields()));
    boost::asio::write(*socket, boost::asio::buffer(*message_content, content_size));
}

//helping function to serialize the short fields of a request body of type send file request
std::string Request::Send_File_Request_Body::serialize_short_fields() {
    std::string serialized_data(SHORT_FIESLDS_SIZE, '\0');
    uint64_t offset = 0;

    add_int_serialization<uint32_t>(serialized_data, content_size, offset);
    add_int_serialization<uint32_t>(serialized_data, orig_size, offset);
    add_int_serialization<uint16_t>(serialized_data, packet_number, offset);
    add_int_serialization<uint16_t>(serialized_data, total_packets, offset);

    std::memcpy(serialized_data.data() + offset, name.data(), name.size());
    return serialized_data;
}



// accessible static functions that allow the useer to conveniently create and send a request
void Request::general_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, std::string& name) {
    Request::check_name_len(name);
    auto bod = std::make_shared<Request_Body>(name);
    auto head = std::make_shared<Request_Header>(id, ver, code, bod->get_len());
    Request req(head, bod);
    req.send_request(socket);
}

void Request::send_key_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, std::string& name, std::string& key) {
    Request::check_name_len(name);
    if (key.size() != PUBLIC_KEY_SIZE)
        throw std::runtime_error("Public key should be of length " + std::to_string(PUBLIC_KEY_SIZE) + "!");

    auto bod = std::make_shared<Send_Key_Request_Body>(name, key);
    auto head = std::make_shared<Request_Header>(id, ver, SEND_PUBLIC_KEY, bod->get_len());
    Request req(head, bod);
    req.send_request(socket);
}

void Request::send_file_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string& file_name, std::shared_ptr<std::string> &content) {
    Request::check_name_len(file_name);
    auto bod = std::make_shared<Send_File_Request_Body>(content_s, orig_s, pack_num, tot_packs, file_name, content);
    auto head = std::make_shared<Request_Header>(id, ver, SEND_FILE, bod->get_len());
    Request req(head, bod);
    req.send_request(socket);
}