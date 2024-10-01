#include <iostream>
#include "client.h"

Client::Client() {
    read_transfer_info();
    connect_to_port();

    if (std::filesystem::exists("me.info")) {
        client_register();
    }
    else {
        client_reconnect();
    }
}

Client::~Client() {
    socket->close();
}

void Client::client_register() {
    std::cout << "Registring client with name \"" << name << "\"\n";
    Request::general_request(socket, uuid, Client::VERSION, Request::REGISTRATION, name);
    Response resp = Response(socket);
    std::cout << "Server responded with code: \"" << Response::CODES_MEANING.at(resp.get_code()) << "\"\n";
    
    if (resp.get_code() == Response::SUCCESSFULL_REGISTRATION) {
        unsigned char * returned_user_id = resp.get_client_id();
        std::memcpy(uuid, returned_user_id, Client::CLIENT_ID_SIZE);
    }
    else {
        throw std::runtime_error("Registration failed.");
    }
}


void Client::client_reconnect() {
}

void Client::connect_to_port() {
    try {
        boost::asio::io_context io_context;
        socket = std::make_shared<tcp::socket>(io_context);
        socket->open(tcp::v4());
    }
    catch (std::exception& e) {
        throw std::runtime_error("Failed to connect to server: " + std::string(e.what()));
    }
}


// returns true if file was read successfully. otherwise prints an error message and returns false.
void Client::read_transfer_info() {
    std::ifstream inputFile("transfer.info");
    std::string ip_and_port;

    if (!inputFile.is_open()) {
        std::cerr << "Error opening transfer.info file. Stopping client activity.\n";
        return;
    }

    // read the first line for IP address and port
    if (!std::getline(inputFile, ip_and_port) && std::getline(inputFile, name) && std::getline(inputFile, file_to_send)) {
        std::cerr << "Error opening transfer.info file. Stopping client activity.\n";
    }

    else {
        std::istringstream iss(ip_and_port);
        std::getline(iss, ip_address, ':'); // read IP address
        std::getline(iss, port); // read port
    }

    inputFile.close();
}

std::string Client::read_file(std::string fname) {
    if (std::filesystem::exists(fname)) {
        std::filesystem::path fpath = fname;
        std::ifstream f1(fname.c_str(), std::ios::binary);

        size_t size = std::filesystem::file_size(fpath);
        char* b = new char[size];
        f1.seekg(0, std::ios::beg);
        f1.read(b, size);
        return b;
    }
    else {
        std::cerr << "Cannot open input file " << fname << std::endl;
        return "";
    }
}
/*
int main() {
    Encryption_Utils::GenerateRSAKeyPair();
}
*/