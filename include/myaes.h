//
// Created by ivan on 22.2.19.
//

#ifndef AESFILE_MYAES_H
#define AESFILE_MYAES_H

#include <array>
#include <fstream>
#include <iostream>
#include "mbedtls/config.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// AES class used for encryption / decryption
// keyBytes is number of bytes for key:
//      (keyBytes == 16) => (key == 128 bit)
//      (keyBytes == 32) => (key == 256 bit)


class AES
{
  public:
    // Key structure for symplifying work with AES key 
    struct Key
    {
      private:
        std::array<unsigned char, 16> iv;
        std::array<unsigned char, 16> key;

        // generates random key with DRBG
        void generateKey();

        // generates random incialization vector with DRBG
        void generateIV();

      public:
        explicit Key();

        explicit Key(std::istream &source);

        Key(std::array<unsigned char, 16> &keyArray, std::array<unsigned char, 16> &ivArray);

        Key(const Key &o) = default;

        Key &operator=(const Key &o) = default;

        void generateNew();

        // import key from file
        void loadFromFile(std::istream &source);

        // export key to file
        void save(std::ostream &os);

        // set aes context "ctx" for encryption
        int setEncContext(mbedtls_aes_context *ctx) const;

        // set aes context "ctx" for decryption
        int setDecContext(mbedtls_aes_context *ctx) const;

        // returns copy of incialization vector
        std::array<unsigned char, 16> incializationVector();
       
    };

  private:
    Key key_;

    // pad 16 bytes block with PKCS#7 padding
    int pad(unsigned char *ptr, unsigned char bytesToPad);

    // remove PKCS#7 padding
    int unpad(const unsigned char *lastByte, size_t &read_);
  public:
    AES();

    explicit AES(const Key &key);

    // encrypts "input" file to "output" file
    size_t encrypt(std::istream &input, std::ostream &output);

    // decrypts "input" file to "output" file
    size_t decrypt(std::istream &input, std::ostream &output, size_t bytes);

    size_t decrypt(std::istream &input, std::ostream &output);


};

// function hashing file
std::array<unsigned char, 64> sha512(std::istream &input);


#endif //AESFILE_MYAES_H
