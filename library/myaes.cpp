//
// Created by ivan on 28.2.19.
//

#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>

#include "mbedtls/config.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "myaes.h"

void AES::Key::generateKey() {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    std::string pers = "aes generate key";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                              &entropy, reinterpret_cast<unsigned char *>(const_cast<char *>(pers.data())),
                              pers.size()))
        throw std::runtime_error("AES KEY Failed to set seed for drbg");

    if (mbedtls_ctr_drbg_random(&ctr_drbg, key.data(), 16))
        throw std::runtime_error("AES KEY Failed to generate random key");

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

// generates random incialization vector with DRBG
void AES::Key::generateIV() {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    std::string pers = "aes generate iv";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                              &entropy, reinterpret_cast<unsigned char *>(const_cast<char *>(pers.data())),
                              pers.size()))
        throw std::runtime_error("AES KEY Failed to set seed for drbg");

    if (mbedtls_ctr_drbg_random(&ctr_drbg, iv.data(), 16))
        throw std::runtime_error("AES KEY Failed to generate random iv");

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

AES::Key::Key() : iv{}, key{} {
    generateKey();
}

AES::Key::Key(std::istream &source) : iv{}, key{} {
    loadFromFile(source);
}

AES::Key::Key(std::array<unsigned char, 16> &keyArray, std::array<unsigned char, 16> &ivArray) : iv(ivArray),
                                                                                                 key(keyArray) {

}


void AES::Key::generateNew() {
    generateIV();
    generateKey();

}

// import key from file
void AES::Key::loadFromFile(std::istream &source) {
    uint16_t keyLen = 0;
    source.read(reinterpret_cast<char *>(&keyLen), 2);
    if (keyLen != 16)
        throw std::runtime_error("Invalid key file");

    source.read(reinterpret_cast<char *>(key.data()), keyLen);
    source.read(reinterpret_cast<char *>(iv.data()), 16);

    if (source.gcount() != 16)
        throw std::runtime_error("invalid key file");

}


// export key to file
void AES::Key::save(std::ostream &os) {
    uint16_t keyLen = 16;
    os.write(reinterpret_cast<char *>(&keyLen), 2);
    os.write(reinterpret_cast<char *>(key.data()), 16);
    os.write(reinterpret_cast<char *>(iv.data()), iv.size());
}

// set aes context "ctx" for encryption
int AES::Key::setEncContext(mbedtls_aes_context *ctx) const {
    return mbedtls_aes_setkey_enc(ctx, key.data(), 16 * 8);
}

// set aes context "ctx" for decryption
int AES::Key::setDecContext(mbedtls_aes_context *ctx) const {
    return mbedtls_aes_setkey_dec(ctx, key.data(), 16 * 8);
}

// returns copy of incialization vector
std::array<unsigned char, 16> AES::Key::incializationVector() { return iv; }


int AES::pad(unsigned char *ptr, unsigned char bytesToPad) {
    if (bytesToPad == 0)
        bytesToPad = 16;
    for (int i = 0; i < bytesToPad; i++)
        *(ptr + i) = bytesToPad;
    return bytesToPad;
}

// remove PKCS#7 padding
int AES::unpad(const unsigned char *lastByte, size_t &read_) {
    unsigned char bytesPaded = *lastByte;

    if (bytesPaded > 16)
        throw std::runtime_error("Invalid padding");
    for (unsigned char i = 1; i < bytesPaded; i++)
        if (*(lastByte - i) != bytesPaded)
            std::cerr << "AES Detected wrong padding at -" << i << " ("
                      << *(lastByte - i) << ")" << '\n';
    read_ -= bytesPaded;
    return bytesPaded;
}

AES::AES() : key_() {
    key_.generateNew();
}

AES::AES(const Key &key) : key_(key) {
}

// encrypts "input" file to "output" file
size_t AES::encrypt(std::istream &input, std::ostream &output) {


    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    key_.setEncContext(&ctx);

    std::array<unsigned char, 16 * 500> dataInBuffer{}, dataOutBuffer{};
    std::array<unsigned char, 16> iv = key_.incializationVector();

    size_t alreadyEncrypted = 0;
    size_t read_ = dataInBuffer.size();
    size_t toWrite = read_;
    while (read_ == dataInBuffer.size()) {
        input.read(reinterpret_cast<char *>(dataInBuffer.data()), dataInBuffer.size());
        read_ = input.gcount();
        toWrite = read_;

        if (read_ != dataInBuffer.size())
            toWrite += pad((dataInBuffer.data() + read_), (16 - read_) % 16);

        if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, toWrite, iv.data(),
                                  dataInBuffer.data(), dataOutBuffer.data()))
            throw std::runtime_error("AES encryption failed");

        output.write(reinterpret_cast<char *>(dataOutBuffer.data()), toWrite);

        alreadyEncrypted += read_;
    }


    mbedtls_aes_free(&ctx);

    return alreadyEncrypted;
}

// decrypts "input" file to "output" file
size_t AES::decrypt(std::istream &input, std::ostream &output, size_t bytes) {

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    key_.setDecContext(&ctx);

    std::array<unsigned char, 16 * 500> dataInBuffer{}, dataOutBuffer{};
    std::array<unsigned char, 16> iv = key_.incializationVector();

    size_t alreadyDecrypted = 0;
    size_t read_ = 0;
    while (input.tellg() < static_cast<ssize_t>(bytes)) {
        input.read(reinterpret_cast<char *>(dataInBuffer.data()),
                   (dataInBuffer.size() < (bytes - alreadyDecrypted) ? dataInBuffer.size() : (bytes -
                                                                                              alreadyDecrypted)));
        read_ = input.gcount();


        if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, read_, iv.data(),
                                  dataInBuffer.data(), dataOutBuffer.data()))
            throw std::runtime_error("AES decryption failed");

        if (alreadyDecrypted + read_ >= bytes)
            unpad((dataOutBuffer.data() + read_ - 1), read_);
        output.write(reinterpret_cast<char *>(dataOutBuffer.data()), read_);

        alreadyDecrypted += read_;
    }

    mbedtls_aes_free(&ctx);
    return alreadyDecrypted;
}

size_t AES::decrypt(std::istream &input, std::ostream &output) {
    auto original = input.tellg();
    input.seekg(0, std::ios::end);
    size_t delta = input.tellg() - original;
    input.seekg(original);
    return decrypt(input, output, delta);

}


// function hashing file
std::array<unsigned char, 64> sha512(std::istream &input) {
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, 0);

    std::array<unsigned char, 64> hash{};
    std::array<unsigned char, 4096> buffer{};
    size_t dataCount = 0;
    do {
        input.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
        mbedtls_sha512_update(&ctx, buffer.data(), input.gcount());
        dataCount += input.gcount();
    } while (input.gcount() == buffer.size());

    mbedtls_sha512_finish(&ctx, hash.data());
    mbedtls_sha512_free(&ctx);

    return hash;
}


