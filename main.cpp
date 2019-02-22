
#include <iostream>
#include <array>
#include <fstream>
#include <algorithm>

#include "mylog.h"
#include "myaes.h"

#include "mbedtls/sha512.h"

struct Status
{
    enum
    {
        NotSet,
        Encrypt,
        Decrypt
    } mode;
    int loglevel;
    std::ifstream input;
    std::ofstream output;
};

std::array<unsigned char, 64> sha512(std::istream &input)
{
    LOG(DEBUG, "SHA512 Generating hash");
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, 0);

    std::array<unsigned char, 64> hash{0};
    std::array<unsigned char, 4096> buffer;
    size_t dataCount = 0;
    do
    {
        input.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
        mbedtls_sha512_update(&ctx, buffer.data(), input.gcount());
        dataCount += input.gcount();
    } while (input.gcount() == buffer.size());
    LOG(DEBUG, "SHA512 hash generated out of %lu bytes", dataCount);

    mbedtls_sha512_finish(&ctx, hash.data());
    mbedtls_sha512_free(&ctx);
    LOG(INFO, "SHA512 hash successfully generated");
    return hash;
}

std::ostream &operator<<(std::ostream &os, std::array<unsigned char, 64> toPrint)
{
    for (const auto &c : toPrint)
    {
        os << std::hex << static_cast<unsigned int>(c) << std::dec;
    }
    return os;
}

char *getCmdOption(char **begin, char **end, const std::string &option)
{
    char **itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(char **begin, char **end, const std::string &option)
{
    return std::find(begin, end, option) != end;
}

int main(int argc, char **argv)
{
    Status status{Status::NotSet, FILTER_INFO, {}, {}};

    if (cmdOptionExists(argv, argv + argc, "-h") || cmdOptionExists(argv, argv + argc, "--help"))
    {
        std::cout << "./pb173_01 [OPTIONS]\n"
                  << "OPTIONS:\n"
                  << "\t-m --mode\tMODE    \tspecifies mode either ENCRYPT or DECRYPT\n"
                  << "\t-o       \tFILENAME\tspecify output file\n"
                  << "\t-i       \tFILENAME\tspecify input file\n"
                  << "\t-k       \tFILENAME\tfile containing key, if does not exists, one is created\n"
                  << "\t-d       \t        \tdebug mode\n"
                  << "Author: Ivan Mitruk\n";
        return 0;
    }

    std::string modeStr;
    if (cmdOptionExists(argv, argv + argc, "--mode"))
        modeStr = getCmdOption(argv, argv + argc, "--mode");
    else if (cmdOptionExists(argv, argv + argc, "-m"))
        modeStr = getCmdOption(argv, argv + argc, "-m");
    else
        throw std::runtime_error("Mode must be specified");

    if (modeStr == "ENCRYPT")
    {
        status.mode = Status::Encrypt;
    }
    else if (modeStr == "DECRYPT")
    {
        status.mode = Status::Decrypt;
    }
    else
    {
        throw std::runtime_error("Unknown mode option");
    }

    if (cmdOptionExists(argv, argv + argc, "-d"))
        status.loglevel = FILTER_DEBUG;

    if (!cmdOptionExists(argv, argv + argc, "-i"))
        throw std::runtime_error("Input file must be specified");

    std::string inputFilename = getCmdOption(argv, argv + argc, "-i");
    status.input.open(inputFilename, std::ios::binary | std::ios::in);
    if (!status.input.is_open())
        throw std::runtime_error("Couldn't open input file");

    std::string outputFilename;
    if (cmdOptionExists(argv, argv + argc, "-o"))
    {

        outputFilename = getCmdOption(argv, argv + argc, "-o");
        status.output.open(outputFilename, std::ios::binary | std::ios::out);
        if (!status.output.is_open())
            throw std::runtime_error("Couldn't open output file");
    }
    else
    {

        outputFilename = inputFilename;
        outputFilename += ".cry";
        status.output.open(outputFilename, std::ios::binary | std::ios::out);
        if (!status.output.is_open())
            throw std::runtime_error("Couldn't open output file");
    }

    if (status.mode == Status::Decrypt && !cmdOptionExists(argv, argv + argc, "-k"))
        throw std::runtime_error("Key have to be specified for decryption");

    startMyLog(OUT_STDERR, status.loglevel, "PB173-HW01");

    try
    {

        AES<16>::Key key;

        if (cmdOptionExists(argv, argv + argc, "-k"))
        {
            std::string keyFilename = getCmdOption(argv, argv + argc, "-k");

            std::ifstream keyFile(keyFilename, std::ios::binary | std::ios::in);
            if (!keyFile.is_open())
            {
                key.generateNew();

                std::ofstream keyFile("random.key", std::ios::binary | std::ios::out);
                if (!keyFile.is_open())
                    LOG(INFO, "Cannot access key file");
                else
                    key.save(keyFile);
            }
            else
                key.loadFromFile(keyFile);
        }
        else
        {
            key.generateNew();

            std::ofstream keyFile("random.key", std::ios::binary | std::ios::out);
            if (!keyFile.is_open())
                LOG(WARN, "Cannot create new key file");
            else
                key.save(keyFile);
        }

        AES<16> crypt(key);
        if (status.mode == Status::Encrypt)
        {

            crypt.encrypt(status.input, status.output);
            status.input.clear();
            status.input.seekg(0);

            std::array<unsigned char, 64> hash = sha512(status.input);
            status.output.write(reinterpret_cast<char *>(hash.data()), 64);
        }
        else
        {
            status.input.seekg(-64, std::ios::end);
            size_t bytes = status.input.tellg();

            status.input.clear();
            status.input.seekg(0);
            crypt.decrypt(status.input, status.output, bytes);

            status.input.clear();
            status.input.seekg(-64, std::ios::end);
            std::array<unsigned char, 64> originalHash, newHash;
            status.input.read(reinterpret_cast<char *>(originalHash.data()), 64);

            std::ifstream decryptedFile(outputFilename);
            newHash = sha512(decryptedFile);

            if (newHash == originalHash)
                LOG(INFO, "OK! Hashes are same");
            else
                LOG(WARN, "Hashes are not the same!");
        }
    }
    catch (std::exception &err)
    {
        LOG(ERR, "Exception: %s", err.what());
    }

    return 0;
}