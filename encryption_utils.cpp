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



using namespace CryptoPP;

std::string Encryption_Utils::GenerateRSAKeyPair() {
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024); //generate random public key
    RSA::PublicKey publicKey(privateKey); //generate public key
    FileSink file("priv.key"); //save private key to file
    privateKey.Save(file);

    std::string publicKeyString;
    StringSink stringSink(publicKeyString);
    publicKey.DEREncode(stringSink);
    std::string base64PublicKey;
    StringSource(publicKeyString, true, new Base64Encoder(new StringSink(base64PublicKey)));

    return base64PublicKey;
}


// Function to read the private key from a file
RSA::PrivateKey LoadPrivateKey(const std::string& filename) {
    RSA::PrivateKey privateKey;
    FileSource file(filename.c_str(), true);
    privateKey.Load(file);
    return privateKey;
}

std::string DecryptAESKey(const std::string& encryptedKey) {
    RSA::PrivateKey privateKey = LoadPrivateKey("priv.key");
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