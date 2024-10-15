#pragma once

/*
* header file for class cliennt and its protocol wrapping class
*/

#include <filesystem>
#include <boost/asio.hpp>
#include <fstream>
#include "response.h"
#include "request.h"
#include "encryption.h"

// main Client class, uses its own methods to perform several requests to server in order to demonstrate it's action
class Client {
public:
	static const int VERSION = 3;
	static const int MAX_TRIES = 3;
	static const size_t CLIENT_ID_SIZE = 16;

private:
	std::string name; // user name
	std::string file_to_send; //name of the file we wish to send (specified in transfer.info)
	unsigned char uuid[CLIENT_ID_SIZE];
	std::string aes_key;
	std::string ip_address;
	std::string port;
	std::shared_ptr<tcp::socket> socket;
	boost::asio::io_context io_context;
	bool active;

	void connect_to_port();
	void read_transfer_info();
	void client_register();
	void read_me_info();
	void client_reconnect();
	void send_public_key();
	void create_me_info();
	void send_file();


public:
	Client();
	~Client();
	void run();
};

// helping functions that ease the use of the protocol for the client.
namespace Protocol_Wrapper {
	std::shared_ptr<Response> make_general_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, std::string& name);
	std::string make_send_key_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, std::string& name, std::string& key);
	unsigned long make_send_file_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, std::string& file_name, std::string& aes_key);
}