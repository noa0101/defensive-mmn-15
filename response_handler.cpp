#include "client.h"

template <typename T> T Response::readnum(std::string& messsage, uint32_t &offset) {
	T value = 0;
	std::memcpy(&value, messsage.data()+offset, sizeof(T));
	value = boost::endian::little_to_native<T>(value);
	offset += sizeof(T);
	return value;
}


Response::Response_Body::Response_Body(std::string body) {
	std::memcpy(client_id, &body, CLIENT_ID_SIZE);
}


Response::Response_Body_With_Key::Response_Body_With_Key(std::string body) : Response_Body(body) {
	encrypted_key.resize(body.size() - CLIENT_ID_SIZE);
	std::memcpy(encrypted_key.data(), &body + CLIENT_ID_SIZE, encrypted_key.size());
}

Response::Valid_CRC_Response_Body::Valid_CRC_Response_Body(std::string body) : Response_Body(body) {
	uint32_t offset = CLIENT_ID_SIZE;
	content_size = readnum<uint32_t>(body, offset);
	file_name.resize(NAME_LEN);
	std::memcpy(file_name.data(), &body + offset, NAME_LEN);
	file_name = std::string(file_name);
	offset += NAME_LEN;
	cksum = Response::readnum<uint32_t>(body, offset);
}

Response::Response_Header::Response_Header(std::shared_ptr<tcp::socket>& socket) {
	std::string serialized_data(HEADER_SIZE, '\0');
	socket->read_some(boost::asio::buffer(serialized_data));
	uint32_t offset = 0;
	version = readnum<uint8_t>(serialized_data, offset);
	code = readnum<uint16_t>(serialized_data, offset);
	payload_size = readnum<uint32_t>(serialized_data, offset);
}


Response::Response_Body::Response_Body() {}

Response::Response(std::shared_ptr<tcp::socket>& socket) : head(socket) {
	std::string message(head.payload_size, '\0');
	socket->read_some(boost::asio::buffer(message));

	switch (head.code) {
	case FILE_RECEIVED:
		body = Valid_CRC_Response_Body(message);
		break;
	case PUBLIC_KEY_RECEIVED:
	case SUCCESSFULL_RECONNECTION:
		body = Response_Body_With_Key(message);
		break;
	default:
		body = Response_Body(message);
	}
}

void Response::print_response_code() {
	std::cout << "Server responded with code " << head.code << ':' << " \"" << Response::CODES_MEANING.at(head.code) << "\"\n";
}

unsigned int Response::get_code() {
	return head.code;
}

unsigned long Response::get_cksum() {
	return body.get_cksum();
}

unsigned char* Response::get_client_id() {
	return body.client_id;
}

std::string Response::Response_Body::get_aes_key() {
	return "";
}

std::string Response::Response_Body_With_Key::get_aes_key() {
	return encrypted_key;
}

std::string Response::get_aes_key() {
	if (head.code == PUBLIC_KEY_RECEIVED || head.code == SUCCESSFULL_RECONNECTION)
		return body.get_aes_key();
}

unsigned long Response::Response_Body::get_cksum() {
	return 0;
}


unsigned long Response::Valid_CRC_Response_Body::get_cksum() {
	return cksum;
}