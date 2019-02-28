//
// Created by ivan on 26.2.19.
//
#define CATCH_CONFIG_NO_CPP17_UNCAUGHT_EXCEPTIONS
#define CATCH_CONFIG_MAIN
#include "myaes.h"
#include <sstream>
#include <array>
#include <iomanip>
#include "catch.hpp"

template<size_t N>
std::ostream &operator<<(std::ostream &os, const std::array<unsigned char, N> &hash) {
    os << std::hex ;
    for (auto & i: hash) {
        os << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
    }
    os << std::dec;
    return os;
}

TEST_CASE("SHA-128 test vectors") {

    std::stringstream input{};
    std::string expected_output{};
    std::stringstream output{};
    SECTION("\"abc\"") {
        input.str("abc");
        expected_output = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    }
    SECTION("\"\"") {
        input.str("");
        expected_output = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    }
    SECTION("\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"") {
        input.str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        expected_output = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445";
    }
    SECTION("\"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu\"") {
        input.str("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        expected_output = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
    }
    SECTION("1000000x\"a\"") {
        input.str(std::string(1000000,'a'));
        expected_output = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
    }
    output << sha512(input);
    REQUIRE(output.str() == expected_output);

}

TEST_CASE("AES-128 test vectors") {
    std::array<unsigned char, 16> key{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                                      0xcf, 0x4f, 0x3c};
    std::array<unsigned char, 16> iv{};
    std::array<unsigned char, 16> input{};
    std::string expected;
    std::array<unsigned char, 16> output{};

    SECTION("Section 1") {
        iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        input = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
        expected = "7649abac8119b246cee98e9b12e9197d";

    }
    SECTION("Section 2") {
        iv = {0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D};
        input = {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
        expected = "5086cb9b507219ee95db113a917678b2";

    }
    SECTION("Section 3") {
        iv = {0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2};
        input = {0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef};
        expected = "73bed6b8e3c1743b7116e69e22229516";
    }
    SECTION("Section 4") {
        iv = {0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16};
        input = {0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
        expected = "3ff1caa1681fac09120eca307586e1a7";
    }


    std::stringstream sIn{};
    std::stringstream sOut{};

    sIn.write(reinterpret_cast<char *>(input.data()), input.size());

    AES::Key aesKey = {key, iv};

    AES enc(aesKey);
    enc.encrypt(sIn, sOut);

    sOut.read(reinterpret_cast<char *>(output.data()), output.size());

    std::stringstream toCompare{};
    toCompare << output;

    REQUIRE(expected == toCompare.str());

}

TEST_CASE("Encrypting and then decrypting") {

    SECTION("with the same key") {
        AES::Key k;
        k.generateNew();

        std::string toEncrypt;
        SECTION("\"\"") {
            toEncrypt = "";
        }
        SECTION("\"0123456789\"") {
            toEncrypt = "0123456789";
        }
        SECTION("1 000 000 x \"a\"") {
            toEncrypt = std::string(1000000, 'a');
        }

        AES enc(k);

        //encrypting
        std::stringstream encIn{toEncrypt};
        std::stringstream encOut;
        enc.encrypt(encIn, encOut);

        //decrypting
        std::stringstream decOut;
        enc.decrypt(encOut, decOut);

        REQUIRE(toEncrypt == decOut.str());
    }


    SECTION("with the different key") {
        AES::Key k1, k2;
        k1.generateNew();
        k2.generateNew();

        std::string toEncrypt;
        SECTION("\"\"") {
            toEncrypt = "";
        }
        SECTION("\"0123456789\"") {
            toEncrypt = "0123456789";
        }
        SECTION("1 000 000 x \"a\"") {
            toEncrypt = std::string(1000000, 'a');
        }

        //encrypting
        AES enc(k1);
        std::stringstream encIn{toEncrypt};
        std::stringstream encOut;
        enc.encrypt(encIn, encOut);

        //decrypting
        AES dec(k2);
        std::stringstream decOut;
        bool threwAnException = false;
        try {
            dec.decrypt(encOut, decOut);
        } catch (...) {
            threwAnException = true;
        }
        REQUIRE((threwAnException || toEncrypt != decOut.str()));
    }
}

TEST_CASE("PADDING TEST") {
    std::vector< char> in1;
    std::vector< char> in2;
    SECTION("padding 16") {
        SECTION("Shortest possible input") {
            in1 = {};
        }
        SECTION("slightly longer input") {
            in1 = std::vector<char>(16, 'a');
        }
        SECTION("very long input") {
            in1 = std::vector<char>(16*100, 'a');
        }

        in2 = in1;
        std::vector<char> tmp(16, 16);
        std::copy(tmp.begin(), tmp.end(), std::back_inserter(in2));
        INFO("padding 16");
    }
    SECTION("padding 15") {

        SECTION("Shortest possible input") {
            in1 = std::vector<char>(1, 'a');
        }
        SECTION("slightly longer input") {
            in1 = std::vector<char>(16 + 1, 'a');
        }
        SECTION("very long input") {
            in1 = std::vector<char>(16*100 + 1, 'a');
        }
        in1 = std::vector<char>('a', 1);
        in2 = in1;
        std::vector<char> tmp(15, 15);
        std::copy(tmp.begin(), tmp.end(), std::back_inserter(in2));
        INFO("padding 15");

    }
    SECTION("padding 14") {

        SECTION("Shortest possible input") {
            in1 = std::vector<char>(2, 'a');
        }
        SECTION("slightly longer input") {
            in1 = std::vector<char>(16 + 2, 'a');
        }
        SECTION("very long input") {
            in1 = std::vector<char>(16*100 + 2, 'a');
        }
        in2 = in1;
        std::vector<char> tmp(14, 14);
        std::copy(tmp.begin(), tmp.end(), std::back_inserter(in2));

        INFO("padding 14");
    }

    SECTION("padding 3") {
        SECTION("Shortest possible input") {
            in1 = std::vector<char>(13, 'a');
        }
        SECTION("slightly longer input") {
            in1 = std::vector<char>(16 + 13, 'a');
        }
        SECTION("very long input") {
            in1 = std::vector<char>(16*100 + 13, 'a');
        }
        in2 = in1;
        std::vector<char> tmp(3, 3);
        std::copy(tmp.begin(), tmp.end(), std::back_inserter(in2));

        INFO("padding 3");
    }

    SECTION("padding 2") {
        SECTION("Shortest possible input") {
            in1 = std::vector<char>(14, 'a');
        }
        SECTION("slightly longer input") {
            in1 = std::vector<char>(16 + 14, 'a');
        }
        SECTION("very long input") {
            in1 = std::vector<char>(16*100 + 14, 'a');
        }
        in2 = in1;
        std::vector<char> tmp(2, 2);
        std::copy(tmp.begin(), tmp.end(), std::back_inserter(in2));

        INFO("padding 2");
    }
    SECTION("padding 1") {
        SECTION("Shortest possible input") {
            in1 = std::vector<char>(15, 'a');
        }
        SECTION("slightly longer input") {
            in1 = std::vector<char>(16 + 15, 'a');
        }
        SECTION("very long input") {
            in1 = std::vector<char>(16*100 + 15, 'a');
        }
        in2 = in1;
        std::vector<char> tmp(1, 1);
        std::copy(tmp.begin(), tmp.end(), std::back_inserter(in2));

        INFO("padding 1");
    }

    AES enc;

    std::stringstream sIn1;
    sIn1.write(in1.data(), in1.size());
    std::stringstream sIn2;
    sIn2.write(in2.data(), in2.size());
    std::stringstream sOut1;
    std::stringstream sOut2;
    enc.encrypt(sIn1, sOut1);
    enc.encrypt(sIn2, sOut2);
    INFO(sOut1.str().length());
    INFO(sOut2.str().length());
    REQUIRE(sOut1.str() == sOut2.str().substr(0, sOut2.str().size() - 16));

}

