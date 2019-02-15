//
// Created by griha on 10.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_IO_MANIP_HPP
#define MIKRONSST_HSM_IO_MANIP_HPP

#include <iostream>
#include <iomanip>

#include <windows.h>

#include <crypto/cipher.hpp>

namespace griha { namespace hsm {

struct _GLE {
    DWORD last_error;
};

inline _GLE
get_last_error(DWORD last_error = ::GetLastError()) {
    return { last_error};
}

//inline _GLE
//get_last_error() {
//    return { .last_error = ::GetLastError()};
//}

template<typename _CharT, typename _Traits>
inline std::basic_ostream<_CharT, _Traits>&
operator<<(std::basic_ostream<_CharT, _Traits>& __os, _GLE __gle) {
    auto fmt_flags = __os.flags();
    __os << '(' << std::showbase << std::hex << std::setfill(__os.widen('0')) << std::setw(8) << __gle.last_error << ')';
    __os.flags(fmt_flags);
    return __os;
}

template<typename _CharT, typename _Traits>
inline std::basic_ostream<_CharT, _Traits>&
last_error(std::basic_ostream<_CharT, _Traits>& __os) {
    return __os << _GLE{::GetLastError()};
}

template<typename _CharT, typename _Traits>
std::basic_ostream<_CharT, _Traits>&
operator<<(std::basic_ostream<_CharT, _Traits>& __os, CipherMode mode) {
    switch (mode) {
        case CipherMode::ECB: __os << "ecb"; break;
        case CipherMode::CBC: __os << "cbc"; break;
        case CipherMode::CFB: __os << "cfb"; break;
        case CipherMode::OFB: __os << "ofb"; break;
        case CipherMode::CTS: __os << "cts"; break;
    }
}

template<typename _CharT, typename _Traits>
std::basic_istream<_CharT, _Traits>&
operator>>(std::basic_istream<_CharT, _Traits>& __is, CipherMode mode) {
    std::basic_string<_CharT, _Traits> str;
    __is >> str;
    if (str.compare("ecb") == 0) mode = CipherMode::ECB;
    else if (str.compare("cbc") == 0) mode = CipherMode::CBC;
    else if (str.compare("cfb") == 0) mode = CipherMode::CFB;
    else if (str.compare("ofb") == 0) mode = CipherMode::OFB;
    else if (str.compare("cts") == 0) mode = CipherMode::CTS;
    else throw std::bad_cast();
}

template<typename _CharT, typename _Traits>
std::basic_ostream<_CharT, _Traits>&
operator<<(std::basic_ostream<_CharT, _Traits>& __os, Padding mode) {
    switch (mode) {
        case Padding::Pkcs5: __os << "pkcs5"; break;
        case Padding::Random: __os << "rand"; break;
        case Padding::Zero: __os << "zero"; break;
    }
}

template<typename _CharT, typename _Traits>
std::basic_istream<_CharT, _Traits>&
operator>>(std::basic_istream<_CharT, _Traits>& __is, Padding mode) {
    std::basic_string<_CharT, _Traits> str;
    __is >> str;
    if (str.compare("pkcs5") == 0) mode = Padding::Pkcs5;
    else if (str.compare("rand") == 0) mode = Padding::Random;
    else if (str.compare("zero") == 0) mode = Padding::Zero;
    else throw std::bad_cast();
}

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_IO_MANIP_HPP
