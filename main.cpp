
#include <iostream>
#include <array>
#include <fstream>
#include <algorithm>
#include "myaes.h"

#include "mbedtls/sha512.h"


// Control structure 
struct Status
{
    enum
    {
        NotSet,
        Encrypt,
        Decrypt
    } mode;
    std::ifstream input;
    std::ofstream output;
};


// returns string after "option" in arguments
char *getCmdOption(char **begin, char **end, const std::string &option)
{
    char **itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return nullptr;
}

// checks whether cmd option was entered
bool cmdOptionExists(char **begin, char **end, const std::string &option)
{
    return std::find(begin, end, option) != end;
}

int main(int argc, char **argv)
{
    // if -h/--help is specified prints help and finishes succesfuly
    if (cmdOptionExists(argv, argv + argc, "-h") || cmdOptionExists(argv, argv + argc, "--help"))
    {
        std::cout << "./pb173_01 [OPTIONS]\n"
                  << "OPTIONS:\n"
                  << "\t-m --mode\tMODE    \tspecifies mode either ENCRYPT or DECRYPT\n"
                  << "\t-o       \tFILENAME\tspecify output file\n"
                  << "\t-i       \tFILENAME\tspecify input file\n"
                  << "\t-k       \tFILENAME\tfile containing key, if does not exists, one is created\n"
                  << "Author: Ivan Mitruk\n";
        return 0;
    }

    // default status structure
    Status status{Status::NotSet, {}, {}};

    // seting specified mode: ENCRYPTION / DECRYPTION
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



    // openinig input file
    if (!cmdOptionExists(argv, argv + argc, "-i"))
        throw std::runtime_error("Input file must be specified");

    std::string inputFilename = getCmdOption(argv, argv + argc, "-i");
    status.input.open(inputFilename, std::ios::binary | std::ios::in);
    if (!status.input.is_open())
        throw std::runtime_error("Couldn't open input file");

    // opennig/creating output file
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
        outputFilename += ".out";
        status.output.open(outputFilename, std::ios::binary | std::ios::out);
        if (!status.output.is_open())
            throw std::runtime_error("Couldn't open output file");
    }

    // enforcing specification of key when trying to decrypt
    if (status.mode == Status::Decrypt && !cmdOptionExists(argv, argv + argc, "-k"))
        throw std::runtime_error("Key have to be specified for decryption");

    // starting my log
    try
    {
        // generating / loading key
        AES::Key key;

        if (cmdOptionExists(argv, argv + argc, "-k"))
        {
            // if keyfile is specified try to load
            std::string keyFilename = getCmdOption(argv, argv + argc, "-k");

            std::ifstream keyFile(keyFilename, std::ios::binary | std::ios::in);
            if (!keyFile.is_open())
            {
                // if opening key file for reading fails, tryies to create new
                key.generateNew();

                std::ofstream keyFile(keyFilename, std::ios::binary | std::ios::out);
                if (!keyFile.is_open())
                    throw std::runtime_error("cannot open key file");
                else
                    key.save(keyFile);
            }
            else
                key.loadFromFile(keyFile);
        }
        else
        {
            // if key file is not specified, generate new and save it
            key.generateNew();

            std::ofstream keyFile("random.key", std::ios::binary | std::ios::out);
            if (!keyFile.is_open())
                throw std::runtime_error("cannot open key file");
            else
                key.save(keyFile);
        }

        AES crypt(key);
        if (status.mode == Status::Encrypt)
        {
            // encrypt file and rewind
            size_t filesize = crypt.encrypt(status.input, status.output);
            std::cout << filesize << "B successfully encrypted\n";

            status.input.clear();
            status.input.seekg(0);

            // generate hash and save it to file
            std::array<unsigned char, 64> hash = sha512(status.input);
            status.output.write(reinterpret_cast<char *>(hash.data()), 64);
        }
        else
        {
            // find where encrypted file ends and hash starts
            status.input.seekg(-64, std::ios::end);
            size_t bytes = status.input.tellg();
            
            // rewind and decrypt file
            status.input.clear();
            status.input.seekg(0);
            size_t filesize = crypt.decrypt(status.input, status.output, bytes);
            std::cout << filesize << "B decrypted";

            // read original hash
            status.input.clear();
            status.input.seekg(-64, std::ios::end);
            std::array<unsigned char, 64> originalHash{}, newHash{};
            status.input.read(reinterpret_cast<char *>(originalHash.data()), 64);
            status.output.close();

            // try generating new hash from decrypted file
            std::ifstream decryptedFile(outputFilename, std::ios::binary | std::ios::in);
            if (!decryptedFile.is_open())
                std::cerr << "Cannot check hash!" << '\n';
            else {
                newHash = sha512(decryptedFile);
                
                // compare hashes and inform user about outcome
                if (newHash == originalHash)
                    std::cout << "OK! hashes are the same" << '\n';
                else
                    std::cerr << "Hashes are not the same!" << '\n';
            }
        }
    }
    catch (std::exception &err)
    {
        std::cerr << "Exception: " << err.what() << '\n';
    }

    return 0;
}
