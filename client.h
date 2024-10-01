#pragma once
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include <string>
#include <memory>
#include <cstdint>
#include <vector>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <map>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <stdexcept>

	
using boost::asio::ip::tcp;

class Request {
public:
	static const unsigned int REGISTRATION = 825;
	static const unsigned int SEND_PUBLIC_KEY = 826;
	static const unsigned int RECONNECTION = 827;
	static const unsigned int SEND_FILE = 828;
	static const unsigned int VALID_CRC = 900;
	static const unsigned int INVALID_CRC = 901;
	static const unsigned int FOURTH_INVALID_CRC = 902;

private:
	static const size_t CLIENT_ID_SIZE = 16;
	static const size_t NAME_LEN = 255;
	static const size_t PUBLIC_KEY_SIZE = 160;

	template <typename T> static void add_int_serialization(std::string, T, uint64_t&);

	class Request_Header {
		unsigned char client_id[CLIENT_ID_SIZE];
		uint8_t version;
		uint16_t code;
		uint32_t payload_size;

	public:
		std::string serialize();
		Request_Header(unsigned char* id, uint8_t ver, uint16_t request_code, uint32_t size);
	};

	class Request_Body {
	protected:
		std::string name;

	public:
		Request_Body(std::string name);
		virtual void send_request_body(std::shared_ptr<tcp::socket>& socket);
		virtual uint32_t get_len();
	};

	class Send_Key_Request_Body : public Request_Body {
		std::string public_key;

	public:
		Send_Key_Request_Body(std::string name, std::string key);
		void send_request_body(std::shared_ptr<tcp::socket>& socket) override;
		uint32_t get_len() override;
	};

	class Send_File_Request_Body : public Request_Body {
		uint32_t content_size;
		uint32_t orig_size;
		uint16_t packet_number;
		uint16_t total_packets;
		char *message_content;

		std::string serialize_short_fields();

	public:
		Send_File_Request_Body(uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string file_name, char* content);
		void send_request_body(std::shared_ptr<tcp::socket>& socket) override;
		uint32_t get_len() override;
	};


	Request_Header head;
	Request_Body body;

	Request(Request_Header head, Request_Body body);
	static void check_name_len(std::string file_name);
	void send_request(std::shared_ptr<tcp::socket>& socket);

public:
	static void general_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, std::string name);
	static void send_key_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, std::string name, std::string key);
	static void send_file_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string file_name, char *content);
};




class Response {
public:
	static const unsigned int SUCCESSFULL_REGISTRATION = 1600;
	static const unsigned int REGISTRATION_FAILED = 1601;
	static const unsigned int PUBLIC_KEY_RECEIVED = 1602;
	static const unsigned int FILE_RECEIVED = 1603;
	static const unsigned int MESSAGE_RECEIVED = 1604;
	static const unsigned int SUCCESSFULL_RECONNECTION = 1605;
	static const unsigned int RECONNECTION_FAILED = 1606;
	static const unsigned int GENERAL_ISSUE = 1607;

	static const std::map<unsigned int, std::string> CODES_MEANING = {
		{SUCCESSFULL_REGISTRATION, "Successful Registration"},
		{REGISTRATION_FAILED, "Registration Failed"},
		{PUBLIC_KEY_RECEIVED, "Public Key Received"},
		{FILE_RECEIVED, "File Received"},
		{MESSAGE_RECEIVED, "Message Received"},
		{SUCCESSFULL_RECONNECTION, "Successful Reconnection"},
		{RECONNECTION_FAILED, "Reconnection Failed"},
		{GENERAL_ISSUE, "General Issue"}
	};

private:
	class Response_Header {
		uint8_t version;
		uint16_t code;
		uint32_t payload_size;

		const unsigned int HEADER_SIZE = sizeof(version) + sizeof(code) + sizeof(payload_size);

		Response_Header(std::shared_ptr<tcp::socket>& socket);

		friend class Response;
	};


	class Response_Body {
	public:
		static const size_t CLIENT_ID_SIZE = 16;
		static const size_t NAME_LEN = 255;

	private:
		unsigned char client_id[CLIENT_ID_SIZE];

	public:
		Response_Body(std::string body);
		Response_Body();

		friend class Response;
	};

	class Response_Body_With_Key : public Response_Body {
		std::string encrypted_key;

	public:
		Response_Body_With_Key(std::string body);
	};

	class Valid_CRC_Response_Body : public Response_Body {
		uint32_t content_size;
		std::string file_name;
		uint32_t cksum;

	public:
		Valid_CRC_Response_Body(std::string body);
	};


	Response_Header head;
	Response_Body body;

protected:
	template <typename T> static T readnum(std::string& messsage, uint32_t& offset);

public:
	Response(std::shared_ptr<tcp::socket>& socket);
	unsigned int get_code();
	unsigned char* get_client_id();
};


namespace Encryption_Utils {
	std::string GenerateRSAKeyPair();
}

namespace Cksum {
	unsigned long memcrc(char* b, size_t n);
}

class Client {
	static const int VERSION = 3;
	static const size_t CLIENT_ID_SIZE = 16;

	std::string name;
	std::string file_to_send;
	unsigned char uuid[CLIENT_ID_SIZE];
	std::string aes_key;
	std::string ip_address;
	std::string port;
	std::shared_ptr<tcp::socket> socket;

	void client_register();
	void client_reconnect();
	void read_transfer_info();
	void connect_to_port();
	std::string read_file(std::string fname);

public:
	Client();
	~Client();
};