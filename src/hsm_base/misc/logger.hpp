//
// Created by griha on 09.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_LOGGER_HPP
#define MIKRONSST_HSM_LOGGER_HPP

#include <string.h>
#include <string>
#include <istream>
#include <sstream>

#include "encoding.hpp"

namespace griha { namespace hsm {

extern const size_t MAX_LINE;

enum class LogType : int8_t {
    Information = 0,
    Warning,
    Error,
    Critical,
    Debug
};

class StandardLog {
public:
    struct Impl;

public:
    StandardLog(const std::string &name, bool debug = false);

    ~StandardLog();

    StandardLog(const StandardLog &rhs) = delete;

    StandardLog &operator=(const StandardLog &rhs) = delete;

    void write(LogType type, const std::string &str);

    inline bool debug() const { return _debug; }

    void debug(bool value);

private:
    Impl *_pimpl;

    bool _debug;
};

template<typename CharT>
class LogStreamBuf : public std::basic_streambuf<CharT> {
public:
    LogStreamBuf(StandardLog &log, LogType type)
            : _plog(&log), _type(type) {
        _buffer.reserve(MAX_LINE);
    }

    ~LogStreamBuf() {
        sync();
    }

    LogStreamBuf(LogStreamBuf &&) = default;

    inline StandardLog &log() { return *_plog; }

    inline const StandardLog &log() const { return *_plog; }

protected:
    typename LogStreamBuf::int_type overflow(typename LogStreamBuf::int_type c) {
        if (c != LogStreamBuf::traits_type::eof()) {
            _buffer.push_back(LogStreamBuf::traits_type::to_char_type(c));
            if (_buffer.capacity() > 0)
                return c;
        }

        if (sync() == -1)
            return LogStreamBuf::traits_type::eof();

        return c;
    }

    int sync() {
        if (!_buffer.empty()) {
            do_write();
            _buffer.clear();
        }

        return 0;
    }

private:
    void do_write();

private:
    StandardLog *_plog;
    LogType _type;
    std::basic_string<CharT> _buffer;
};

template<>
inline void LogStreamBuf<char>::do_write() {
    _plog->write(_type, _buffer);
}

template<>
inline void LogStreamBuf<wchar_t>::do_write() {
    _plog->write(_type, from_wstr(_buffer));
}

template<typename CharT>
class LogStream : public std::basic_ostream<CharT> {
public:
    LogStream(StandardLog &log, LogType type)
            : std::basic_ostream<CharT>(nullptr)
            , _buf(log, type) { this->rdbuf(&_buf); }

    LogStream(LogStream &&) = default;

private:
    LogStreamBuf<CharT> _buf;
};

using LogStreamA = LogStream<char>;
using LogStreamW = LogStream<wchar_t>;

}} // namespace griha::hsm

#define DECLARE_LOG(Type, Name) griha::hsm:: Type ## Log __log__(Name)
#define DECLARE_LOG_DEBUG(Type, Name) griha::hsm:: Type ## Log __log__(Name, true)

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

#define LOG_INFO_A griha::hsm::LogStreamA( __log__, griha::hsm::LogType::Information ) << ""
#define LOG_WARN_A griha::hsm::LogStreamA( __log__, griha::hsm::LogType::Warning ) << __FILENAME__ << ":" << __LINE__ << ": "
#define LOG_ERROR_A griha::hsm::LogStreamA( __log__, griha::hsm::LogType::Error ) << __FILENAME__  << ":" << __LINE__ << ": "
#define LOG_CRITICAL_A griha::hsm::LogStreamA( __log__, griha::hsm::LogType::Critical ) << __FILENAME__  << ":" << __LINE__ << ": "
#define LOG_DEBUG_A griha::hsm::LogStreamA( __log__, griha::hsm::LogType::Debug ) << __FILENAME__  << ":" << __LINE__ << ": "

#define LOG_INFO_W griha::hsm::LogStreamW( __log__, griha::hsm::LogType::Information ) << ""
#define LOG_WARN_W griha::hsm::LogStreamW( __log__, griha::hsm::LogType::Warning ) << __FILENAME__ << ":" << __LINE__ << ": "
#define LOG_ERROR_W griha::hsm::LogStreamW( __log__, griha::hsm::LogType::Error ) << __FILENAME__  << ":" << __LINE__ << ": "
#define LOG_CRITICAL_W griha::hsm::LogStreamW( __log__, griha::hsm::LogType::Critical ) << __FILENAME__  << ":" << __LINE__ << ": "
#define LOG_DEBUG_W griha::hsm::LogStreamW( __log__, griha::hsm::LogType::Debug ) << __FILENAME__  << ":" << __LINE__ << ": "

#define LOG_INFO LOG_INFO_A
#define LOG_WARN LOG_WARN_A
#define LOG_ERROR LOG_ERROR_A
#define LOG_CRITICAL LOG_CRITICAL_A
#define LOG_DEBUG LOG_DEBUG_A

#define DEFINE_LOG griha::hsm::StandardLog __log__
#define LOG __log__

extern DEFINE_LOG;

#endif //MIKRONSST_HSM_LOGGER_HPP
