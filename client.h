#pragma once
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include <string>
#include <memory>
#include <cstdint>
#include <vector>
#include <filesystem>
#include <string>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <map>
#include <math.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <cryptlib.h>
#include <rsa.h>


	
using boost::asio::ip::tcp;

class Request {
public:
	static const uint16_t REGISTRATION = 825;
	static const uint16_t SEND_PUBLIC_KEY = 826;
	static const uint16_t RECONNECTION = 827;
	static const uint16_t SEND_FILE = 828;
	static const uint16_t VALID_CRC = 900;
	static const uint16_t INVALID_CRC = 901;
	static const uint16_t FOURTH_INVALID_CRC = 902;

private:
	static const size_t CLIENT_ID_SIZE = 16;
	static const size_t NAME_LEN = 255;
	static const size_t PUBLIC_KEY_SIZE = 160;

	template <typename T> static void add_int_serialization(std::string&, T, uint64_t&);

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
		Send_Key_Request_Body(std::string &name, std::string &key);
		void  send_request_body(std::shared_ptr<tcp::socket>& socket) override;
		uint32_t get_len() override;
	};

	class Send_File_Request_Body : public Request_Body {
		uint32_t content_size;
		uint32_t orig_size;
		uint16_t packet_number;
		uint16_t total_packets;
		std::shared_ptr<std::string> message_content;

		std::string serialize_short_fields();

	public:
		static const size_t SHORT_FIESLDS_SIZE = sizeof(content_size) + sizeof(orig_size) + sizeof(packet_number) + sizeof(total_packets) + NAME_LEN;
		Send_File_Request_Body(uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string& file_name, std::shared_ptr<std::string>& content);
		void send_request_body(std::shared_ptr<tcp::socket>& socket) override;
		uint32_t get_len() override;
	};


	std::shared_ptr<Request_Header> head;
	std::shared_ptr<Request_Body> body;

	Request(std::shared_ptr<Request_Header> head, std::shared_ptr<Request_Body> body);
	static void check_name_len(std::string &file_name);
	void send_request(std::shared_ptr<tcp::socket>& socket);

public:
	static const size_t MAX_FILE_SENT_SIZE = ((size_t)1 << (4 * 8)) - Send_File_Request_Body::SHORT_FIESLDS_SIZE; //maximal length of a file that can be sent in one request (limited by the size of payload_size)
	static void general_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, std::string &name);
	static void send_key_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, std::string &name, std::string& key);
	static void send_file_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string &file_name, std::shared_ptr<std::string> &content);
};




class Response {
public:
	static const uint16_t SUCCESSFULL_REGISTRATION = 1600;
	static const uint16_t REGISTRATION_FAILED = 1601;
	static const uint16_t PUBLIC_KEY_RECEIVED = 1602;
	static const uint16_t FILE_RECEIVED = 1603;
	static const uint16_t MESSAGE_RECEIVED = 1604;
	static const uint16_t SUCCESSFULL_RECONNECTION = 1605;
	static const uint16_t RECONNECTION_FAILED = 1606;
	static const uint16_t GENERAL_ISSUE = 1607;

	inline static const std::map<unsigned int, std::string> CODES_MEANING = {
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

	public:
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
		Response_Body(std::string &body);
		virtual std::string get_aes_key();
		virtual unsigned long get_cksum();
		friend class Response;
	};

	class Response_Body_With_Key : public Response_Body {
		std::string encrypted_key;

	public:
		Response_Body_With_Key(std::string &body);
		std::string get_aes_key();
		friend class Response;
	};

	class Valid_CRC_Response_Body : public Response_Body {
		uint32_t content_size;
		std::string file_name;
		uint32_t cksum;

	public:
		Valid_CRC_Response_Body(std::string &body);
		unsigned long get_cksum();

		friend class Response;
	};

	std::shared_ptr<Response_Header> head;
	std::shared_ptr<Response_Body> body;

protected:
	template <typename T> static T readnum(std::string& messsage, uint32_t& offset);

public:
	Response(std::shared_ptr<tcp::socket>& socket);
	unsigned char* get_client_id();
	void print_response_code();
	unsigned int get_code();
	unsigned long get_cksum();
	std::string get_aes_key();
};



namespace Encryption_Utils {
	std::string generate_RSA_keyPair();
	CryptoPP::RSA::PrivateKey load_private_key(const std::string& filename);
	std::string decrypt_AES_key(const std::string& encryptedKey);
	std::shared_ptr<std::string> AES_encryption(char* plaintext, std::string& key);
	std::string get_encoded_privkey();
}

namespace Cksum {
	unsigned long memcrc(char* b, size_t n);
	unsigned long get_cksum(std::string &fname);
}

class Client {
public:
	static const int VERSION = 3;
	static const int MAX_TRIES = 3;
	static const size_t CLIENT_ID_SIZE = 16;

private:
	std::string name;
	std::string file_to_send;
	unsigned char uuid[CLIENT_ID_SIZE];
	std::string aes_key;
	std::string ip_address;
	std::string port;
	std::shared_ptr<tcp::socket> socket;
	bool active;
	boost::asio::io_context io_context;


	void client_register();
	void client_reconnect();
	void read_transfer_info();
	void read_me_info();
	void connect_to_port();
	void send_public_key();
	void send_file();
	bool send_file_single_request(char* content, uint16_t packet_num, uint16_t tot_packs);
	void create_me_info();


public:
	Client();
	~Client();
	void run();
};

namespace Protocol_Wrapper {
	std::shared_ptr<Response> make_general_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, std::string& name);
	std::string make_send_key_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, std::string& name, std::string& key);
	unsigned long make_send_file_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, std::string& file_name, std::string& aes_key);
}