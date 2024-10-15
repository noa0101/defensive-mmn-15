#include "response.h"
/*
* This file contains methods of the class Response, to read and parse the server's responses according to protocol.
*/

// function to read a number of type T from the socket (assumes little endian representation)
template <typename T> T Response::readnum(std::string& messsage, uint32_t &offset) {
	T value = 0;
	std::memcpy(&value, messsage.data()+offset, sizeof(T));
	value = boost::endian::little_to_native<T>(value);
	offset += sizeof(T);
	return value;
}

// constructor for Response class. reads the server's response from the sokcet.
Response::Response(std::shared_ptr<tcp::socket>& socket)
	: head(std::make_shared<Response_Header>(socket)) {
	std::string message(head->payload_size, '\0');
	socket->read_some(boost::asio::buffer(message));

	// initialize body based on the response code
	switch (head->code) {
	case FILE_RECEIVED:
		body = std::make_shared<Valid_CRC_Response_Body>(message);
		break;
	case PUBLIC_KEY_RECEIVED:
	case SUCCESSFULL_RECONNECTION:
		body = std::make_shared<Response_Body_With_Key>(message);
		break;
	default:
		body = std::make_shared<Response_Body>(message);
	}
}

// prints the server's response code.
void Response::print_response_code() {
	if (Response::CODES_MEANING.find(head->code) == Response::CODES_MEANING.end())
		throw std::runtime_error("Server responded with unknown code: " + std::to_string(head->code) + ".\n");

	std::cout << "----------------------------------------------------------------\n";
	std::cout << "Server responded with code " << head->code << ':' << " \"" << Response::CODES_MEANING.at(head->code) << "\"\n";
	std::cout << "----------------------------------------------------------------\n\n";
}

//constructor for response header - reads the response header from the socket
Response::Response_Header::Response_Header(std::shared_ptr<tcp::socket>& socket) {
	std::string serialized_data(HEADER_SIZE, '\0');
	socket->read_some(boost::asio::buffer(serialized_data));
	uint32_t offset = 0;
	version = readnum<uint8_t>(serialized_data, offset);
	code = readnum<uint16_t>(serialized_data, offset);
	payload_size = readnum<uint32_t>(serialized_data, offset);
}

//constructors for different response body types
Response::Response_Body::Response_Body(std::string &body) {
	std::memcpy(client_id, body.data(), CLIENT_ID_SIZE);
}

Response::Response_Body_With_Key::Response_Body_With_Key(std::string &body) : Response_Body(body) {
	encrypted_key.resize(body.size() - CLIENT_ID_SIZE);
	std::memcpy(encrypted_key.data(), body.data() + CLIENT_ID_SIZE, encrypted_key.size());
}

Response::Valid_CRC_Response_Body::Valid_CRC_Response_Body(std::string &body) : Response_Body(body) {
	uint32_t offset = CLIENT_ID_SIZE;
	content_size = readnum<uint32_t>(body, offset);
	file_name.resize(NAME_LEN);
	std::memcpy(file_name.data(), body.data() + offset, NAME_LEN);
	file_name = std::string(file_name);
	offset += NAME_LEN;
	cksum = Response::readnum<uint32_t>(body, offset);
}

// getters
unsigned int Response::get_code() {
	return head->code;
}

unsigned char* Response::get_client_id() {
	return body->client_id;
}

unsigned long Response::get_cksum() {
	return body->get_cksum();
}

unsigned long Response::Response_Body::get_cksum() {
	return 0; // virtual getter, meant to be overriden if the body is of type Valid_CRC_Response_Body - returns junk value.
}

unsigned long Response::Valid_CRC_Response_Body::get_cksum() {
	return cksum;
}

std::string Response::get_aes_key() {
	if (head->code == PUBLIC_KEY_RECEIVED || head->code == SUCCESSFULL_RECONNECTION)
		return body->get_aes_key();
	else
		return "";
}

std::string Response::Response_Body::get_aes_key() {
	return ""; // virtual getter, meant to be overriden if the body is of type Response_Body_With_Key - returns junk value.
}

std::string Response::Response_Body_With_Key::get_aes_key() {
	return encrypted_key;
}