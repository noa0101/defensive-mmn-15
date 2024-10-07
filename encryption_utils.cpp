#include "client.h"
#include <iostream>
#include <cryptlib.h>
#include <osrng.h>
#include <rsa.h>
#include <files.h>
#include <secblock.h>
#include <hex.h>
#include <filters.h>
#include <base64.h>
#include <modes.h>


std::string Encryption_Utils::generate_RSA_keyPair() {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024); //generate random public key
    CryptoPP::RSA::PublicKey publicKey(privateKey); //generate public key
    CryptoPP::FileSink file("priv.key", true); //save private key to file
    privateKey.Save(file);

    std::string publicKeyString;
    CryptoPP::StringSink ss(publicKeyString);
    publicKey.Save(ss);
    return publicKeyString;
}


// Function to read the private key from a file
CryptoPP::RSA::PrivateKey Encryption_Utils::load_private_key(const std::string& filename) {
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::FileSource file(filename.c_str(), true);
    privateKey.Load(file);
    return privateKey;
}

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

    // Return the unique_ptr containing the cipherText
    return cipherText;
}