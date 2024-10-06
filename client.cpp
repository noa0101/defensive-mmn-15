#include <iostream>
#include "client.h"

Client::Client() : active(true) {
    try {
        read_transfer_info();
        connect_to_port();
    }
    catch (std::exception& e) {
        active = false;
        std::cerr << "Fatal Error!\n" << e.what() << '\n' << "Stopping Client actievity.\n";
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
        std::cerr << "Fatal Error!\n" << e.what() << '\n' << "Stopping Client actievity.\n";
    }
}


void Client::client_register() {
    std::cout << "Registring client with name \"" << name << "\"\n";

    bool success = false;
    for (int tries = 0; !success && tries < MAX_TRIES; tries++) {
        Request::general_request(socket, uuid, Client::VERSION, Request::REGISTRATION, name);
        Response resp = Response(socket);
        resp.print_response_code();
        if (resp.get_code() == Response::SUCCESSFULL_REGISTRATION) {
            unsigned char* returned_user_id = resp.get_client_id();
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
    // read private key from priv.key, where the encryption utils function saved it
    std::string priv_key;
    std::ifstream key_file("priv.key");
    if (!key_file)
        throw std::runtime_error("Failed to open file priv.key\n");
    getline(key_file, priv_key);
    key_file.close();

    // open me.info with std::ios::trunc to clear the previous file contents if it exists
    std::ofstream outputFile("me.info", std::ios::out | std::ios::trunc);
    if (!outputFile)
        throw std::runtime_error("Failed to create or open file me.info\n");

    // write the necessary lines
    outputFile << name << '\n';
    outputFile << uuid << '\n';
    outputFile << priv_key << '\n';

    outputFile.close();
}


void Client::client_reconnect() {
    std::cout << "Reconnecting client " << name << ".\n";
    bool success = false;
    for (int tries = 0; !success && tries < MAX_TRIES; tries++) {
        Request::general_request(socket, uuid, VERSION, Request::RECONNECTION, name);
        Response resp = Response(socket);
        resp.print_response_code();
        if (resp.get_code() == Response::SUCCESSFULL_RECONNECTION) {
            aes_key = Encryption_Utils::decrypt_AES_key(resp.get_aes_key());
            success = true;
        }
        else if (resp.get_code() == Response::RECONNECTION_FAILED) {
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
    std::cout << "public key size: " << public_key.size() << '\n';

    bool success = false;
    for (int tries = 0; !success && tries < MAX_TRIES; tries++) {
        Request::send_key_request(socket, uuid, VERSION, Request::SEND_PUBLIC_KEY, name, public_key);
        Response resp = Response(socket);
        resp.print_response_code();
        if (resp.get_code() == Response::PUBLIC_KEY_RECEIVED) {
            aes_key = Encryption_Utils::decrypt_AES_key(resp.get_aes_key());
            success = true;
        }
    }
    if(!success)
        throw std::runtime_error("Key sending went wrong.");
}

void Client::connect_to_port() {
    std::cout << "Connecting to port " << port << ".\n";
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


/*char * Client::read_file(std::string fname) {
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
}*/

void Client::send_file() {
    std::cout << "Sending a file for backup.\n";

    std::ifstream file(file_to_send);
    if (!file.is_open())
        throw std::runtime_error("Error opening file to send" + file_to_send + '.');

    unsigned long cksum = Cksum::get_cksum(file_to_send);

    size_t file_size = file.tellg();
    char* buffer = new char[Request::MAX_FILE_SENT_SIZE + 1]; // +1 for null terminator
    uint16_t tot_packs = ceil((double)file_size / Request::MAX_FILE_SENT_SIZE);
    uint16_t packet_num;
    bool validated = false;
    int tries = 0;

    do {
        packet_num = 1;
        while (!file.eof()) {
            file.read(buffer, Request::MAX_FILE_SENT_SIZE);
            std::streamsize bytesRead = file.gcount(); // Get the number of bytes actually read
            buffer[bytesRead] = '\0'; // Null terminate the buffer

            if (!send_file_single_request(buffer, packet_num, tot_packs)) {
                delete[] buffer;
                file.close();
                throw std::runtime_error("Server did not receive file as expected.");
            }

            packet_num++;
        }

        Response resp(socket);
        resp.print_response_code();



        if (resp.get_code() == Response::FILE_RECEIVED && cksum == resp.get_cksum()) {
            Request::general_request(socket, uuid, VERSION, Request::VALID_CRC, file_to_send);
            validated = true;
            std::cout << "File received with correct cksum.\n";
            Response resp(socket);
            resp.print_response_code();
        }

        else {
            if (tries == MAX_TRIES) {
                std::cout << "File not received/received with incorrect cksum for the fourth time. Sending abortion message.\n";
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

    } while (!validated && tries < MAX_TRIES);

    delete[] buffer; // Clean up the heap-allocated buffer
    file.close();
}

//tries to send a single packet of a file. returns true is sending was successfull, false if failed thrice.
bool Client::send_file_single_request(char *plaintext, uint16_t packet_num, uint16_t tot_packs) {
    char* ciphertext = Encryption_Utils::AES_encryption(plaintext, aes_key);
    for (int tries = 0; tries < MAX_TRIES; tries++) {
        Request::send_file_request(socket, uuid, VERSION, Request::SEND_FILE, strlen(ciphertext), strlen(plaintext), packet_num, tot_packs, file_to_send, ciphertext);
        Response resp(socket);
        resp.print_response_code();

        if (resp.get_code() == Response::FILE_RECEIVED) {
            delete[] ciphertext;
            return true;
        }
    }
    //if this line is reached, it means the sending failed thrice
    delete[] ciphertext;
    return false;
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
