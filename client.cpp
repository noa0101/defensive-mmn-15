/*
* This file contains the main functions that opperate the client.
*/

#include <iostream>
#include "client.h"

using boost::asio::ip::tcp;

// constructor for client class. initializes its connection to the port.
Client::Client() : active(true) {
    try {
        read_transfer_info();
        connect_to_port();
    }
    catch (std::exception& e) {
        active = false; //in case connection to the port has failed, stop activity.
        //print error message in red font
        std::cerr << "\033[1m\033[31m" << "Fatal Error!\n" << e.what() << '\n' << "Stopping Client actievity.\n" << "\033[0m" << std::endl; 
    }
}

// function that makes the wanted requests by the server: 
// registration+sending private key/reconnection and then sending the file specified in transfer.info
void Client::run() {
    if (!active) return; // in case there has been an error in the initialization of the server, it will not run.
    try {
        if (std::filesystem::exists("me.info")) { // if this client has ran before
            read_me_info();
            client_reconnect();
        }
        else {
            client_register(); // register and send a private key
        }
        
        send_file();
    }
    catch (std::exception& e) {
        active = false; // in case of unhandled exception, stop client activity
        std::cerr << "\033[1m\033[31m" << "Fatal Error!\n" << e.what() << '\n' << "Stopping Client actievity.\n" << "\033[0m" << std::endl;  //print error message in red font
    }
}

// function to send registration request, send a private key and set up me.info file
void Client::client_register() {
    std::cout << "Registering client with name \"" << name << "\"\n";

    bool success = false;
    for (int tries = 0; !success && tries < MAX_TRIES; tries++) { // if requests fail, try again up to MAX_TRIES (3) times
        auto resp = Protocol_Wrapper::make_general_request(socket, uuid, Client::VERSION, Request::REGISTRATION, name);
        if (resp->get_code() == Response::SUCCESSFULL_REGISTRATION) {
            unsigned char* returned_user_id = resp->get_client_id();
            std::memcpy(uuid, returned_user_id, Client::CLIENT_ID_SIZE);
            success = true;
        }
    }
    if(!success) // if failed thrice, stop client activity and announce fatal error.
        throw std::runtime_error("Registration failed.");

    send_public_key();
    create_me_info();
}

//function to create the me.info file
void Client::create_me_info() {
    // open me.info with std::ios::trunc to clear the previous file contents if it exists
    std::ofstream outputFile("me.info", std::ios::out | std::ios::trunc);
    if (!outputFile)
        throw std::runtime_error("Failed to create or open file me.info\n");

    outputFile << name << '\n';

    // Write UUID in hexadecimal format
    for (size_t i = 0; i < sizeof(uuid); ++i)
        outputFile << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(uuid[i]);
    outputFile << '\n';
    
    outputFile << Encryption_Utils::get_encoded_privkey() << '\n';

    outputFile.close();
}

// sends reconnection request to server.
void Client::client_reconnect() {
    std::cout << "Reconnecting client " << name << ".\n";
    bool success = false;
    for (int tries = 0; !success && tries < MAX_TRIES; tries++) { // if request failes, try again up to thrice
        auto resp = Protocol_Wrapper::make_general_request(socket, uuid, VERSION, Request::RECONNECTION, name);
        if (resp->get_code() == Response::SUCCESSFULL_RECONNECTION) {
            aes_key = Encryption_Utils::decrypt_AES_key(resp->get_aes_key());
            success = true;
        }
        else if (resp->get_code() == Response::RECONNECTION_FAILED) { // in case of response "RECONNECTION FAILED", register.
            client_register();
            return;
        }
    }
    if(!success)
        throw std::runtime_error("Server refused reconnection thrice.");
}

// generates a pair of keys and sends the public one to the server.
void Client::send_public_key() {
    std::cout << "Generating and sending public key to server.\n";
    std::string public_key = Encryption_Utils::generate_RSA_keyPair();

    bool success = false;
    for (int tries = 0; !success && tries < MAX_TRIES; tries++) { // try up to thrice
        aes_key = Protocol_Wrapper::make_send_key_request(socket, uuid, VERSION, name, public_key);
        if(aes_key.size())
            success = true;
    }
    if(!success)
        throw std::runtime_error("Key sending went wrong.");
}

// function to connect to the port
void Client::connect_to_port() {
    std::cout << "Connecting on port " << port << ".\n";
    try {
        socket = std::make_shared<tcp::socket>(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(*socket, resolver.resolve(ip_address, port));
    }
    catch (std::exception& e) {
        throw std::runtime_error("Failed to connect to port: " + std::string(e.what()));
    }

}


// returns true if file was read successfully. otherwise prints an error message and returns false.
void Client::read_transfer_info() {
    std::ifstream inputFile("transfer.info");
    std::string ip_and_port;

    if (!inputFile.is_open()) {
        throw std::runtime_error("Error opening transfer.info file.");
    }

    // read the first line for IP address and port
    if (!(std::getline(inputFile, ip_and_port) && std::getline(inputFile, name) && std::getline(inputFile, file_to_send))) { // if transfer.info is mal-formed
        throw std::runtime_error("Content of transfer.info is not as expected.");
    }

    else {
        std::istringstream iss(ip_and_port);
        std::getline(iss, ip_address, ':'); // read IP address
        std::getline(iss, port); // read port
    }

    inputFile.close();
}

//reads me.info file and updates the Client parameters accordingly.
void Client::read_me_info() {
    std::cout << "This client has ran before. Reading 'me.info'\n";
    std::ifstream inputFile("me.info");
    std::string ip_and_port;
    std::string user_id_string;
    if (!inputFile.is_open()) {
        throw std::runtime_error("Error opening transfer.info file.");
    }

    if (!(std::getline(inputFile, ip_and_port) && std::getline(inputFile, user_id_string))) { // if me.info is mal-formed
        throw std::runtime_error("Content of me.info is not as expected.");
    }

    // convert string representation of uuid into the char representation
    for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
        std::string byteString = user_id_string.substr(i * 2, 2);
        uuid[i] = static_cast<char>(std::stoi(byteString, nullptr, 16));
    }
}

// sends a file to server, responds to correctness of returned CRC
void Client::send_file() {
    std::cout << "sending file '" + file_to_send + "' for backup.\n";
    unsigned long cksum = Cksum::get_cksum(file_to_send);

    bool validated = false;
    int tries = 0;

    do { // try sending file up to MAX_TRIES times.
        unsigned long server_cksum = Protocol_Wrapper::make_send_file_request(socket, uuid, VERSION, file_to_send, aes_key); // send the file

        if (cksum == server_cksum) { //if CFC is correct
            std::cout << "File received with correct cksum. Sending validation message.\n";
            auto resp = Protocol_Wrapper::make_general_request(socket, uuid, VERSION, Request::VALID_CRC, file_to_send);
            validated = true;
        }

        else { // CRC is false
            if (tries == MAX_TRIES) {
                // in this case (last try, CRC isn't valid), send abortion message
                std::cout << "File not received/received with incorrect cksum for the fourth time. Sending abortion message.\n";
                auto resp = Protocol_Wrapper::make_general_request(socket, uuid, VERSION, Request::FOURTH_INVALID_CRC, file_to_send);
            }
            else {
                Protocol_Wrapper::make_general_request(socket, uuid, VERSION, Request::INVALID_CRC, file_to_send);
                std::cout << "File received with incorrect cksum.\n";
            }
        }

        tries++;

    } while (!validated && tries <= MAX_TRIES);
}

// destructor for class client - disconnects from the socket and closes it.
Client::~Client() {
    if (!socket || !socket->is_open()) return;
    try {
        socket->shutdown(tcp::socket::shutdown_send);
        socket->close();
    }
    catch (std::exception& e) {
        std::cerr << "Error while closing the socket: " << e.what() << std::endl;
    }
}


// main function to start the client activity
int main() {
    Client client;
    client.run();
}