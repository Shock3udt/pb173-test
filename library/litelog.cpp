//
// Created by ivan on 26.2.19.
//

#include "litelog.h"


using namespace ll;
Log ll::logging;

std::ostream &operator<<(std::ostream &os, MessageLevel i) {
    switch (i) {
        case MessageLevel::Info:
            os << "Info";
            break;
        case MessageLevel::Debug:
            os << "Debug";
            break;
        case MessageLevel::Warning:
            os << "\033[31mWarning\033[0m";
            break;
        case MessageLevel::Error:
            os << "\033[31mError\033[0m";
            break;
        default:
            std::runtime_error("Cannot print None type log message");
    }

    return os;
}

void Log::flush() {
    for (auto &out : outputs) {
        if (out.second & current) {
            out.first << entity_ << ":" << current << ":" << buffer.str() << std::endl;
        }
    }

    std::stringstream ss{};
    buffer.swap(ss);
}

Log::Log(std::string entity)
        : openFiles{}, outputs{{std::cerr, MessageLevel::Error | MessageLevel::Warning},
                               {std::cout, MessageLevel::None}}, entity_(std::move(entity)), buffer{},
          current{MessageLevel::None} {}

Log::Log() : Log(__FILE__) {}

std::string &Log::identity() { return entity_; }

const std::string &Log::identity() const { return entity_; }

void Log::setOutputLevel(std::ofstream &os, unsigned short lvl = MessageLevel::Info) {
    if (auto i = std::find_if(openFiles.begin(), openFiles.end(), [&os](std::ostream &l) { return &l == &os; }); i !=
                                                                                                                 openFiles.end()) {
        std::find_if(outputs.begin(), outputs.end(), [&i](std::pair<std::ostream &, unsigned short> &s) {
            return &(*i) == &(s.first);
        })->second = lvl;
    } else {
        std::ofstream &nos = openFiles.emplace_back();
        nos.swap(os);

        outputs.emplace_back(nos, lvl);
    }
}

void Log::setOutputLevel(std::ostream &os, unsigned short lvl = MessageLevel::Info) {
    if (auto i = std::find_if(openFiles.begin(), openFiles.end(), [&os](std::ostream &l) { return &l == &os; }); i !=
                                                                                                                 openFiles.end()) {
        std::find_if(outputs.begin(), outputs.end(), [&i](std::pair<std::ostream &, unsigned short> &s) {
            return &(*i) == &(s.first);
        })->second = lvl;
    } else {
        throw std::runtime_error("Cannot set output level to this string");
    }
}

void Log::addStderrLevel(MessageLevel lvl) {
    outputs.begin()->second = lvl;
}



