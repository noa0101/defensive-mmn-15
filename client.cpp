#include <iostream>
#include "client.h"

Client::Client() {
    try {
        read_transfer_info();
        connect_to_port();

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
        std::cerr << "Fatal error: " << e.what() << '\n' << "Stopping Client actievity.\n";
    }
}

Client::~Client() {
    if(socket && socket->is_open())
        socket->close();
}

void Client::client_register() {
    std::cout << "Registring client with name \"" << name << "\"\n";
    Request::general_request(socket, uuid, Client::VERSION, Request::REGISTRATION, name);
    Response resp = Response(socket);
    resp.print_response_code();

    if (resp.get_code() == Response::SUCCESSFULL_REGISTRATION) {
        unsigned char * returned_user_id = resp.get_client_id();
        std::memcpy(uuid, returned_user_id, Client::CLIENT_ID_SIZE);
    }
    else {
        throw std::runtime_error("Registration failed.");
    }
    send_public_key();


    //craete me.info
    std::ofstream outputFile("me.info");
    std::string priv_key;
    std::ifstream key_file("priv.key");
    getline(key_file, priv_key);
    key_file.close();

    outputFile << name << '\n';
    outputFile << uuid << '\n';
    outputFile << priv_key << '\n';
}


void Client::client_reconnect() {
    Request::general_request(socket, uuid, VERSION, Request::RECONNECTION, name);
    Response resp = Response(socket);
    resp.print_response_code();
    if (resp.get_code() == Response::SUCCESSFULL_RECONNECTION) {
        aes_key = Encryption_Utils::decrypt_AES_key(resp.get_aes_key());
    }
    else {
        throw std::runtime_error("Reconnection went wrong.");
    }
}

void Client::send_public_key() {
    std::cout << "Generating and sending public key to server.\n";
    std::string public_key = Encryption_Utils::generate_RSA_keyPair();
    Request::send_key_request(socket, uuid, VERSION, Request::SEND_PUBLIC_KEY, name, public_key);
    Response resp = Response(socket);
    resp.print_response_code();
    if (resp.get_code() == Response::PUBLIC_KEY_RECEIVED) {
        aes_key = Encryption_Utils::decrypt_AES_key(resp.get_aes_key());
    }
    else {
        throw std::runtime_error("Key sending went wrong.");
    }
}

void Client::connect_to_port() {
    try {
        boost::asio::io_context io_context;
        tcp::socket s(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(s, resolver.resolve(ip_address, port));
        socket = std::make_shared<tcp::socket>(s);
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


char * Client::read_file(std::string fname) {
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
        throw std::runtime_error("Requested input file \"" + fname + "\" was not found.");
    }
}

void Client::send_file() {
    std::cout << "Sending a file for backup.\n";
    char* plaintext = read_file(file_to_send);
    char* ciphertext = Encryption_Utils::AES_encryption(plaintext, aes_key);
    unsigned long cksum = Cksum::memcrc(plaintext, strlen(plaintext));

    unsigned short tries = 0;
    bool validated = false;

    while (tries <= MAX_TRIES && !validated) {
        Request::send_file_request(socket, uuid, VERSION, Request::SEND_FILE, strlen(ciphertext), strlen(plaintext), 0, 0, file_to_send, ciphertext);
        Response resp(socket);
        resp.print_response_code();

        if (resp.get_code() != Response::FILE_RECEIVED) {
            delete[] plaintext;
            delete[] ciphertext;
            throw std::runtime_error("Server did not receive file as expected.");
        }

        unsigned long server_cksum = resp.get_cksum();
        if (cksum == server_cksum) {
            Request::general_request(socket, uuid, VERSION, Request::VALID_CRC, file_to_send);
            validated = true;
            std::cout << "File received with correct cksum.\n";
            Response resp(socket);
            resp.print_response_code();
        }
        else {
            if (tries == MAX_TRIES) {
                std::cout << "File received with incorrect cksum for the fourth time. Sending abortion message.\n";
                Request::general_request(socket, uuid, VERSION, Request::FOURTH_INVALID_CRC, file_to_send);
                Response resp(socket);
                resp.print_response_code();

            }
            else {
                Request::general_request(socket, uuid, VERSION, Request::INVALID_CRC, file_to_send);
                std::cout << "File received with incorrect cksum.\n";
            }
        }
        tries++;
    }

    // deallocate heap memory
    delete[] plaintext;
    delete[] ciphertext;
}


int main() {
    Client client;
}
