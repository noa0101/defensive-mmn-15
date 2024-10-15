/*
* THis file contains wrapper functions for existing Cryptopp functions, for easier and custom use of the client.
*/

#include "encryption.h"

// function to generate an RSA key pair.
// Returns the public key as a string and saves private key into the file priv.key
std::string Encryption_Utils::generate_RSA_keyPair() {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024); //generate random public key
    CryptoPP::RSA::PublicKey publicKey(privateKey); //generate public key
    CryptoPP::FileSink file("priv.key", true); 
    privateKey.Save(file); //save private key to file

    std::string publicKeyString;
    CryptoPP::StringSink ss(publicKeyString);
    publicKey.Save(ss); // save public key into a string
    return publicKeyString;
}


// Function to read the private key from a file
CryptoPP::RSA::PrivateKey Encryption_Utils::load_private_key(const std::string& filename) {
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::FileSource file(filename.c_str(), true);
    privateKey.Load(file);
    return privateKey;
}

// returns the private key encoded in base 64, for convenient saving in file me.info
std::string Encryption_Utils::get_encoded_privkey() {
    CryptoPP::RSA::PrivateKey privateKey = Encryption_Utils::load_private_key("priv.key");
    std::string encoded_key;
    std::string private_key_str;

    CryptoPP::StringSink ss(private_key_str);
    privateKey.DEREncode(ss);

    // Base64 encode the private key string
    CryptoPP::StringSource(private_key_str, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded_key)
        )
    );

    return encoded_key;
}

// receives a string (for the use of the client, the encrypted AES key received from the server) and returns its decryption using the RSA private key.
std::string Encryption_Utils::decrypt_AES_key(const std::string& encryptedKey) {
    CryptoPP::RSA::PrivateKey privateKey = load_private_key("priv.key");
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    std::string decryptedAESKey;

    CryptoPP::StringSource ss(encryptedKey, true,
        new CryptoPP::PK_DecryptorFilter(rng, decryptor,
            new CryptoPP::StringSink(decryptedAESKey)
        )
    );
    return decryptedAESKey;
}

// receivs a string (assumes null terminated) and an AES key and returns its encryption.
// works on the heap to allow for relatively long texts.
std::shared_ptr<std::string> Encryption_Utils::AES_encryption(char* plaintext, std::string& key) {
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };
    CryptoPP::SecByteBlock keyBlock(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());

    // Use unique_ptr for cipherText
    auto cipherText = std::make_shared<std::string>();

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(keyBlock, keyBlock.size(), iv);

        CryptoPP::StringSource ss(plaintext, true,
            new CryptoPP::StreamTransformationFilter(encryptor,
                new CryptoPP::StringSink(*cipherText) // Write to the dereferenced unique_ptr
            )
        );

    }
    catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Encryption failed: " + std::string(e.what()));
    }

    // Return the shared_ptr containing the cipherText
    return cipherText;
}