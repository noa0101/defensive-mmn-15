#include "client.h"

//returns cksum returned by the server, or a default value of 0 if the server returned with error
unsigned long Protocol_Wrapper::make_send_file_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, std::string& file_name, std::string &aes_key) {
    std::ifstream file(file_name);
    if (!file.is_open())
        throw std::runtime_error("Error opening file to send: " + file_name + '.');

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg(); // Get the size of the file
    file.seekg(0, std::ios::beg); // Move the file pointer back to the beginning
    
    char* buffer = new char[Request::MAX_FILE_SENT_SIZE + 1]; // +1 for null terminator
    uint16_t tot_packs = ceil((double)file_size / Request::MAX_FILE_SENT_SIZE);
    uint16_t packet_num;
 
    packet_num = 1;
    while (packet_num <= tot_packs) {
        file.read(buffer, Request::MAX_FILE_SENT_SIZE);
        std::streamsize bytesRead = file.gcount(); // Get the number of bytes actually read
        buffer[bytesRead] = '\0'; // Null terminate the buffer

        auto ciphertext = Encryption_Utils::AES_encryption(buffer, aes_key);
        Request::send_file_request(socket, id, ver, ciphertext->size(), file_size, packet_num, tot_packs, file_name, ciphertext);
        packet_num++;
    }

    Response resp(socket);
    resp.print_response_code();
    delete[] buffer; // Clean up the heap-allocated buffer
    file.close();
    return resp.get_cksum();
}

//send public key and gets server response, returns the decrypted aes key if all went well of nullptr if server responded with error
std::string Protocol_Wrapper::make_send_key_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, std::string& name, std::string& key) {
    try {
        Request::send_key_request(socket, id, ver, name, key);
        Response resp = Response(socket);
        resp.print_response_code();
        if (resp.get_code() == Response::PUBLIC_KEY_RECEIVED)
            return Encryption_Utils::decrypt_AES_key(resp.get_aes_key());
        else
            return "";
    }
    catch (std::exception& e) {
        throw std::runtime_error("Connection has been cut off.");
    }
}

//returns the response of the server or nullptr if there is non
std::shared_ptr<Response> Protocol_Wrapper::make_general_request(std::shared_ptr<tcp::socket>& socket, unsigned char id[], uint8_t ver, uint16_t code, std::string& name) {
    Request::general_request(socket, id, ver, code, name);
    if (code == Request::INVALID_CRC)
        return nullptr;
    else {
        try {
            auto response = std::make_shared<Response>(socket);
            response->print_response_code();
            return response;
        }
        catch (std::exception& e) {
            throw std::runtime_error("Connection has been cut off.");
        }
    }
}