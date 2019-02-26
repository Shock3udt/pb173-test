//
// Created by ivan on 26.2.19.
//

#ifndef LITELOG_LITELOG_H
#define LITELOG_LITELOG_H

#include <iostream>
#include <sstream>
#include <fstream>
#include <list>
#include <algorithm>
#include <random>
#include <iomanip>

namespace ll {
    enum MessageLevel {
        None = 0, Error = 1, Warning = 0b10, Info = 0b100, Debug = 0b1000
    };


    class Log {
        std::list<std::ofstream> openFiles;
        std::list<std::pair<std::ostream &, unsigned short>> outputs;
        std::string entity_;

        std::stringstream buffer;
        MessageLevel current;

        void flush();

    public:
        explicit Log(std::string);

        explicit Log();

        std::string &identity();

        const std::string &identity() const;

        void setOutputLevel(std::ofstream &, unsigned short);

        void setOutputLevel(std::ostream &, unsigned short);

        Log &operator<<(const MessageLevel &i) {
            flush();
            current = i;
            return *this;
        }

        void addStderrLevel(MessageLevel lvl);

        template<typename T>
        Log &operator<<(const T &i) {
            buffer << i;

            return *this;
        }


        ~Log() { flush(); }
    };


    extern Log logging;
};

std::ostream &operator<<(std::ostream &, ll::MessageLevel);


#endif //LITELOG_LITELOG_H
