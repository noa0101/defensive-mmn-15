#pragma once

/*
* header file for request handling
*/

#include <iomanip>
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>


using boost::asio::ip::tcp;


class Request {
public:
	// request codes
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

	class Request_Body { // for general requests (with no special structure)
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
		Send_Key_Request_Body(std::string& name, std::string& key);
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

	// class Request attributes
	std::shared_ptr<Request_Header> head;
	std::shared_ptr<Request_Body> body;

	Request(std::shared_ptr<Request_Header> head, std::shared_ptr<Request_Body> body);
	static void check_name_len(std::string& file_name);
	void send_request(std::shared_ptr<tcp::socket>& socket);

public:
	static const size_t MAX_FILE_SENT_SIZE = 1024; //maximal length of a file that can be sent in one request (limit to avoid very big packets)
	static void general_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, std::string& name);
	static void send_key_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, std::string& name, std::string& key);
	static void send_file_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint32_t content_s, uint32_t orig_s, uint16_t pack_num, uint16_t tot_packs, std::string& file_name, std::shared_ptr<std::string>& content);
};