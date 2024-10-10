#include <iostream>
#include "client.h"

Client::Client() : active(true) {
    try {
        read_transfer_info();
        connect_to_port();
    }
    catch (std::exception& e) {
        active = false;
        std::cerr << "\033[1m\033[31m" << "Fatal Error!\n" << e.what() << '\n' << "Stopping Client actievity.\n" << "\033[0m" << std::endl; //print error message in red font

    }
}

void Client::run() {
    if (!active) return;
    try {
        if (std::filesystem::exists("me.info")) {
            read_me_info();
            client_reconnect();
        }
        else {
            client_register();
        }
        
        send_file();
    }
    catch (std::exception& e) {
        active = false;
        std::cerr << "\033[1m\033[31m" << "Fatal Error!\n" << e.what() << '\n' << "Stopping Client actievity.\n" << "\033[0m" << std::endl;  //print error message in red font
    }
}


void Client::client_register() {
    std::cout << "Registring client with name \"" << name << "\"\n";

    bool success = false;
    for (int tries = 0; !success && tries < MAX_TRIES; tries++) {
        auto resp = Protocol_Wrapper::make_general_request(socket, uuid, Client::VERSION, Request::REGISTRATION, name);
        if (resp->get_code() == Response::SUCCESSFULL_REGISTRATION) {
            unsigned char* returned_user_id = resp->get_client_id();
            std::memcpy(uuid, returned_user_id, Client::CLIENT_ID_SIZE);
            success = true;
        }
    }
    if(!success)
        throw std::runtime_error("Registration failed.");

    send_public_key();
    create_me_info();
}


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


void Client::client_reconnect() {
    std::cout << "Reconnecting client " << name << ".\n";
    bool success = false;
    for (int tries = 0; !success && tries < MAX_TRIES; tries++) {
        auto resp = Protocol_Wrapper::make_general_request(socket, uuid, VERSION, Request::RECONNECTION, name);
        if (resp->get_code() == Response::SUCCESSFULL_RECONNECTION) {
            aes_key = Encryption_Utils::decrypt_AES_key(resp->get_aes_key());
            success = true;
        }
        else if (resp->get_code() == Response::RECONNECTION_FAILED) {
            client_register();
            return;
        }
    }
    if(!success)
        throw std::runtime_error("Server refused reconnection thrice.");
}

void Client::send_public_key() {
    std::cout << "Generating and sending public key to server.\n";
    std::string public_key = Encryption_Utils::generate_RSA_keyPair();

    bool success = false;
    for (int tries = 0; !success && tries < MAX_TRIES; tries++) {
        aes_key = Protocol_Wrapper::make_send_key_request(socket, uuid, VERSION, name, public_key);
        if(aes_key.size())
            success = true;
    }
    if(!success)
        throw std::runtime_error("Key sending went wrong.");
}

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
    if (!(std::getline(inputFile, ip_and_port) && std::getline(inputFile, name) && std::getline(inputFile, file_to_send))) {
        throw std::runtime_error("Content of transfer.info is not as expected.");
    }

    else {
        std::istringstream iss(ip_and_port);
        std::getline(iss, ip_address, ':'); // read IP address
        std::getline(iss, port); // read port
    }

    inputFile.close();
}

void Client::read_me_info() {
    std::cout << "This client has ran before. Reading 'me.info'\n";
    std::ifstream inputFile("me.info");
    std::string ip_and_port;
    std::string user_id_string;
    if (!inputFile.is_open()) {
        throw std::runtime_error("Error opening transfer.info file.");
    }

    if (!(std::getline(inputFile, ip_and_port) && std::getline(inputFile, user_id_string))) {
        throw std::runtime_error("Content of me.info is not as expected.");
    }

    // convert string representation of uuid into the char representation
    for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
        std::string byteString = user_id_string.substr(i * 2, 2);
        uuid[i] = static_cast<char>(std::stoi(byteString, nullptr, 16));
    }
}


void Client::send_file() {
    std::cout << "sending file '" + file_to_send + "' for backup.\n";
    unsigned long cksum = Cksum::get_cksum(file_to_send);

    bool validated = false;
    int tries = 0;

    do {
        unsigned long server_cksum = Protocol_Wrapper::make_send_file_request(socket, uuid, VERSION, file_to_send, aes_key);
        tries++;

        if (cksum == server_cksum) {
            std::cout << "File received with correct cksum. Sending validation message.\n";
            auto resp = Protocol_Wrapper::make_general_request(socket, uuid, VERSION, Request::VALID_CRC, file_to_send);
            validated = true;
        }

        else {
            if (tries == MAX_TRIES) {
                std::cout << "File not received/received with incorrect cksum for the fourth time. Sending abortion message.\n";
                auto resp = Protocol_Wrapper::make_general_request(socket, uuid, VERSION, Request::FOURTH_INVALID_CRC, file_to_send);
            }
            else {
                Protocol_Wrapper::make_general_request(socket, uuid, VERSION, Request::INVALID_CRC, file_to_send);
                std::cout << "File received with incorrect cksum.\n";
            }
        }
    } while (!validated && tries < MAX_TRIES);
}

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


int main() {
    Client client;
    client.run();
}
