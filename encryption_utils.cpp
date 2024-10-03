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
    
    /*
    std::string publicKeyString;
    StringSink stringSink(publicKeyString);
    std::string base64PublicKey;
    StringSource(publicKeyString, true, new Base64Encoder(new StringSink(base64PublicKey)));

    return base64PublicKey;*/
}


// Function to read the private key from a file
CryptoPP::RSA::PrivateKey Encryption_Utils::load_private_key(const std::string& filename) {
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::FileSource file(filename.c_str(), true);
    privateKey.Load(file);
    return privateKey;
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


char* Encryption_Utils::AES_encryption(char* plaintext, std::string& key) {
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

    CryptoPP::SecByteBlock keyBlock(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    std::string cipherText;

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(keyBlock, keyBlock.size(), iv);

        CryptoPP::StringSource ss(plaintext, true,
            new CryptoPP::StreamTransformationFilter(encryptor,
                new CryptoPP::StringSink(cipherText)
            )
        );

    }
    catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Encryption failed: " + std::string(e.what()));
    }

    char* output = new char[cipherText.size()];
    memcpy(output, cipherText.data(), cipherText.size());

    return output;
}