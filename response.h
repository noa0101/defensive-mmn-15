#pragma once

/*
* header file for response handling
*/

#include <iomanip>
#include <map>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>

using boost::asio::ip::tcp;


class Response {
public:
	// response codes
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
		Response_Body(std::string& body);
		virtual std::string get_aes_key();
		virtual unsigned long get_cksum();
		friend class Response;
	};

	class Response_Body_With_Key : public Response_Body {
		std::string encrypted_key;

	public:
		Response_Body_With_Key(std::string& body);
		std::string get_aes_key();
		friend class Response;
	};

	class Valid_CRC_Response_Body : public Response_Body {
		uint32_t content_size;
		std::string file_name;
		uint32_t cksum;

	public:
		Valid_CRC_Response_Body(std::string& body);
		unsigned long get_cksum();
		friend class Response;
	};

	// class Response attributes
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