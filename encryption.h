#pragma once

/*
* header file for encryption utils and cksum namespaces
*/

#include <cryptlib.h>
#include <osrng.h>
#include <rsa.h>
#include <files.h>
#include <secblock.h>
#include <hex.h>
#include <filters.h>
#include <base64.h>
#include <modes.h>


namespace Encryption_Utils {
	std::string generate_RSA_keyPair();
	CryptoPP::RSA::PrivateKey load_private_key(const std::string& filename);
	std::string decrypt_AES_key(const std::string& encryptedKey);
	std::shared_ptr<std::string> AES_encryption(char* plaintext, size_t length, std::string& key);
	std::string get_encoded_privkey();
}

namespace Cksum {
	unsigned long memcrc(char* b, size_t n);
	unsigned long get_cksum(std::string& fname);
}