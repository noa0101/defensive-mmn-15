#pragma once
#include <iomanip>
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
	
using boost::asio::ip::tcp;

#define VESRION 3


class Request {
private:
	static const unsigned int REGISTRATION = 825;
	static const unsigned int SEND_PUBLIC_KEY = 826;
	static const unsigned int RECONNECTION = 827;
	static const unsigned int SEND_FILE = 828;
	static const unsigned int VALID_CRC = 900;
	static const unsigned int INVALID_CRC = 901;
	static const unsigned int FOURTH_INVALID_CRC = 902;

	static const unsigned int CLIENT_ID_SIZE = 16;
	static const unsigned int NAME_LEN = 255;
	static const unsigned int PUBLIC_KEY_SIZE = 160;

	template <typename T> static void add_int_serialization(std::string, T, uint64_t&);

	class Request_Header {
		unsigned char client_id[CLIENT_ID_SIZE];
		uint8_t version;
		uint16_t code;
		uint32_t payload_size;

	public:
		std::string serialize();
		Request_Header(unsigned char* id, uint8_t ver, uint16_t request_code, uint64_t size);
	};

	class Send_File_Request_Body {
		uint32_t content_size;
		uint32_t orig_size;
		uint16_t packet_number;
		uint16_t total_packets;
		std::string file_name;
		std::string message_content;

	public:
		std::string serialize();
		Send_File_Request_Body(uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string file_name, std::string content):
			content_size(content_s), orig_size(orig_s), packet_number(pack_num),
			total_packets(tot_packs), file_name(file_name), message_content(content) {}
	};


	Request_Header head;
	std::string payload;

	Request(unsigned char id[], uint8_t ver, uint16_t code, std::string payload);
	static void check_name_len(std::string file_name);

public:
	std::string serialize();
	static Request generate_general_request(unsigned char id[], uint8_t ver, uint16_t code, std::string name);
	static Request generate_send_key_request(unsigned char id[], uint8_t ver, uint16_t code, std::string name, std::string key);
	static Request generate_send_file_request(unsigned char id[], uint8_t ver, uint16_t code, uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string file_name, std::string content);
};