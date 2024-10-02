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


using namespace CryptoPP;

std::string Encryption_Utils::generate_RSA_keyPair() {
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024); //generate random public key
    RSA::PublicKey publicKey(privateKey); //generate public key
    FileSink file("priv.key"); //save private key to file
    privateKey.Save(file);

    std::string publicKeyString;
    StringSink stringSink(publicKeyString);
    std::string base64PublicKey;
    StringSource(publicKeyString, true, new Base64Encoder(new StringSink(base64PublicKey)));

    return base64PublicKey;
}


// Function to read the private key from a file
RSA::PrivateKey Encryption_Utils::load_private_key(const std::string& filename) {
    RSA::PrivateKey privateKey;
    FileSource file(filename.c_str(), true);
    privateKey.Load(file);
    return privateKey;
}

std::string Encryption_Utils::decrypt_AES_key(const std::string& encryptedKey) {
    RSA::PrivateKey privateKey = load_private_key("priv.key");
    AutoSeededRandomPool rng;

    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    std::string decryptedAESKey;

    StringSource ss(encryptedKey, true,
        new PK_DecryptorFilter(rng, decryptor,
            new StringSink(decryptedAESKey)
        )
    );
    return decryptedAESKey;
}


char* Encryption_Utils::AES_encryption(char* plaintext, std::string& key) {
    byte iv[AES::BLOCKSIZE] = { 0 };

    SecByteBlock keyBlock(reinterpret_cast<const byte*>(key.data()), key.size());
    std::string cipherText;

    try {
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(keyBlock, keyBlock.size(), iv);

        StringSource ss(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(cipherText)
            )
        );

    }
    catch (const Exception& e) {
        throw std::runtime_error("Encryption failed: " + std::string(e.what()));
    }

    char* output = new char[cipherText.size()];
    memcpy(output, cipherText.data(), cipherText.size());

    return output;
}