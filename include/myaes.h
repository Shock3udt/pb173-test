//
// Created by ivan on 22.2.19.
//

#ifndef AESFILE_MYAES_H
#define AESFILE_MYAES_H

#include <array>
#include "litelog.h"
#include <cstdint>
#include <fstream>

#include "mbedtls/config.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// AES class used for encryption / decryption
// keyBytes is number of bytes for key:
//      (keyBytes == 16) => (key == 128 bit)
//      (keyBytes == 32) => (key == 256 bit)
template<size_t N>
ll::Log &operator<<(ll::Log &os, std::array<unsigned char, N> &input) {
    for (unsigned i = 0; i < N; i++) {
        os << static_cast<int>(input[i]) << " ";
    }
    return os;
}


template <size_t keyBytes>
class AES
{
  public:
    // Key structure for symplifying work with AES key 
    struct Key
    {
      private:
        std::array<unsigned char, 16> iv;
        std::array<unsigned char, keyBytes> key;

        // generates random key with DRBG
        void generateKey()
        {
            mbedtls_ctr_drbg_context ctr_drbg;
            mbedtls_entropy_context entropy;
            std::string pers = "aes generate key";

            mbedtls_entropy_init(&entropy);
            mbedtls_ctr_drbg_init(&ctr_drbg);

            if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                      &entropy, reinterpret_cast<unsigned char *>(const_cast<char *>(pers.data())), pers.size()))
                throw std::runtime_error("AES KEY Failed to set seed for drbg");

            if (mbedtls_ctr_drbg_random(&ctr_drbg, key.data(), keyBytes))
                throw std::runtime_error("AES KEY Failed to generate random key");

            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);
        }

        // generates random incialization vector with DRBG
        void generateIV()
        {
            mbedtls_ctr_drbg_context ctr_drbg;
            mbedtls_entropy_context entropy;
            std::string pers = "aes generate iv";

            mbedtls_entropy_init(&entropy);
            mbedtls_ctr_drbg_init(&ctr_drbg);

            if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                      &entropy, reinterpret_cast<unsigned char *>(const_cast<char *>(pers.data())), pers.size()))
                throw std::runtime_error("AES KEY Failed to set seed for drbg");

            if (mbedtls_ctr_drbg_random(&ctr_drbg, iv.data(), 16))
                throw std::runtime_error("AES KEY Failed to generate random iv");

            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);
        }

      public:
        explicit Key() : iv{}, key{}
        {
            static_assert(keyBytes == 16 || keyBytes == 32);
            ll::logging << ll::MessageLevel::Debug << "empty key (" << keyBytes << ") object created";
        }

        explicit Key(std::istream &source) : iv{}, key{}
        {
            static_assert(keyBytes == 16 || keyBytes == 32);
            loadFromFile(source);
        }

        void generateNew()
        {
            generateIV();
            generateKey();

            ll::logging << ll::MessageLevel::Info << "New key generated";
            ll::logging << ll::MessageLevel::Debug << "AES key: " << key;
            ll::logging << ll::MessageLevel::Debug << "AES iv: " << iv;
        }

        // import key from file
        void loadFromFile(std::istream &source)
        {
            uint16_t keyLen = 0;
            source.read(reinterpret_cast<char *>(&keyLen), 2);
            if (keyLen != keyBytes)
                throw std::runtime_error("Invalid key file");

            source.read(reinterpret_cast<char *>(key.data()), keyLen);
            source.read(reinterpret_cast<char *>(iv.data()), 16);

            if (source.gcount() != 16)
                throw std::runtime_error("invalid key file");

            ll::logging << ll::MessageLevel::Info << "Key loaded from file";
            ll::logging << ll::MessageLevel::Debug << "AES key" << key;
            ll::logging << ll::MessageLevel::Debug << "AES iv:" << iv;
        }


        // export key to file
        void save(std::ostream &os)
        {
            uint16_t keyLen = keyBytes;
            os.write(reinterpret_cast<char *>(&keyLen), 2);
            os.write(reinterpret_cast<char *>(key.data()), keyBytes);
            os.write(reinterpret_cast<char *>(iv.data()), iv.size());
        }

        // set aes context "ctx" for encryption
        int setEncContext(mbedtls_aes_context *ctx)
        {
            return mbedtls_aes_setkey_enc(ctx, key.data(), keyBytes * 8);
        }

        // set aes context "ctx" for decryption
        int setDecContext(mbedtls_aes_context *ctx)
        {
            return mbedtls_aes_setkey_dec(ctx, key.data(), keyBytes * 8);
        }

        // returns copy of incialization vector
        std::array<unsigned char, 16> incializationVector() { return iv; }
       
        // returns bitsize of key
        size_t bitSize() { return keyBytes * 8; }
    };

  private:
    Key key_;

    // pad 16 bytes block with PKCS#7 padding
    int pad(unsigned char *ptr, unsigned char bytesToPad)
    {
        if (bytesToPad == 0)
            bytesToPad = 16;
        ll::logging << ll::MessageLevel::Debug << "AES padding " << bytesToPad << " bytes";
        for (int i = 0; i < bytesToPad; i++)
            *(ptr + i) = bytesToPad;
        return bytesToPad;
    }

    // remove PKCS#7 padding
    int unpad(const unsigned char *lastByte, size_t &read_)
    {
        unsigned char bytesPaded = *lastByte;

        ll::logging << ll::MessageLevel::Debug << "Padding " << bytesPaded << " bytes detected";
        if (bytesPaded > 16)
            throw std::runtime_error("Invalid padding");
        for (unsigned char i = 1; i < bytesPaded; i++)
            if (*(lastByte - i) != bytesPaded)
                ll::logging << ll::MessageLevel::Warning << "AES Detected wrong padding at -" << i << " ("
                            << *(lastByte - i) << ")";
        read_ -= bytesPaded;
        return bytesPaded;
    }

  public:
    AES() : key_()
    {
        ll::logging << ll::MessageLevel::Debug << "AES Creating object with random genereated key";
        key_.generateNew();
    }

    explicit AES(Key key) : key_(std::move(key))
    {
        ll::logging << ll::MessageLevel::Debug << "AES Creating object with supplied key";
    }

    // encrypts "input" file to "output" file
    void encrypt(std::istream &input, std::ostream &output)
    {

        ll::logging << ll::MessageLevel::Debug << "AES Starting encryption";

        ll::logging << ll::MessageLevel::Debug << "AES Setting up aes context";
        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        key_.setEncContext(&ctx);

        std::array<unsigned char, 16 * 500> dataInBuffer{}, dataOutBuffer{};
        std::array<unsigned char, 16> iv = key_.incializationVector();

        size_t alreadyEncrypted = 0;
        size_t read_ = dataInBuffer.size();
        size_t toWrite = read_;
        while (read_ == dataInBuffer.size())
        {
            input.read(reinterpret_cast<char *>(dataInBuffer.data()), dataInBuffer.size());
            read_ = input.gcount();
            toWrite = read_;

            ll::logging << ll::MessageLevel::Debug << "AES " << read_ << " data read";
            if (read_ != dataInBuffer.size())
                toWrite += pad((dataInBuffer.data() + read_), (16 - read_) % 16);

            if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, toWrite, iv.data(),
                                      dataInBuffer.data(), dataOutBuffer.data()))
                throw std::runtime_error("AES encryption failed");

            output.write(reinterpret_cast<char *>(dataOutBuffer.data()), toWrite);

            alreadyEncrypted += read_;
            ll::logging << ll::MessageLevel::Debug << "AES " << alreadyEncrypted << " bytes encrypted";
        }

        ll::logging << ll::MessageLevel::Info << "AES successfully encrypted " << alreadyEncrypted << " bytes";

        mbedtls_aes_free(&ctx);
    }

    // decrypts "input" file to "output" file
    void decrypt(std::istream &input, std::ostream &output, size_t bytes)
    {
        ll::logging << ll::MessageLevel::Debug << "AES Starting decryption";

        ll::logging << ll::MessageLevel::Debug << "AES Setting up aes context";
        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        key_.setDecContext(&ctx);

        std::array<unsigned char, 16 * 500> dataInBuffer{}, dataOutBuffer{};
        std::array<unsigned char, 16> iv = key_.incializationVector();

        size_t alreadyDecrypted = 0;
        size_t read_ = 0;
        while (input.tellg() < static_cast<ssize_t>(bytes))
        {
            input.read(reinterpret_cast<char *>(dataInBuffer.data()), (dataInBuffer.size() < (bytes - alreadyDecrypted) ? dataInBuffer.size() : (bytes - alreadyDecrypted)));
            read_ = input.gcount();

            ll::logging << ll::MessageLevel::Debug << "AES " << read_ << " data read";

            if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, read_, iv.data(),
                                      dataInBuffer.data(), dataOutBuffer.data()))
                throw std::runtime_error("AES decryption failed");

            if (alreadyDecrypted + read_ >= bytes)
                unpad((dataOutBuffer.data() + read_ - 1), read_);
            output.write(reinterpret_cast<char *>(dataOutBuffer.data()), read_);

            alreadyDecrypted += read_;
            ll::logging << ll::MessageLevel::Debug << "AES " << alreadyDecrypted << " bytes decrypted";
        }

        ll::logging << ll::MessageLevel::Info << "AES successfully decrypted " << alreadyDecrypted << " bytes";
        mbedtls_aes_free(&ctx);
    }

    ~AES()
    {
        ll::logging << ll::MessageLevel::Debug << "AES Destroying object";
    }
};

// function hashing file
inline std::array<unsigned char, 64> sha512(std::istream &input)
{
    ll::logging << ll::MessageLevel::Debug << "SHA512 Generating hash";
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, 0);

    std::array<unsigned char, 64> hash{};
    std::array<unsigned char, 4096> buffer{};
    size_t dataCount = 0;
    do
    {
        input.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
        mbedtls_sha512_update(&ctx, buffer.data(), input.gcount());
        dataCount += input.gcount();
        ll::logging << ll::MessageLevel::Debug << "SHA512 already processed " << dataCount << ", last read "
                    << input.gcount();
    } while (input.gcount() == buffer.size());
    ll::logging << ll::MessageLevel::Debug << "SHA512 hash generated out of " << dataCount << " bytes";

    mbedtls_sha512_finish(&ctx, hash.data());
    mbedtls_sha512_free(&ctx);
    ll::logging << ll::MessageLevel::Info << "SHA512 hash successfully generated";
    return hash;
}


#endif //AESFILE_MYAES_H
