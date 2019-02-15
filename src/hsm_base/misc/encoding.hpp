//
// Created by griha on 09.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_ENCODING_HPP
#define MIKRONSST_HSM_ENCODING_HPP

#include <stdlib.h>
#include <string>

namespace griha { namespace hsm {

inline std::wstring to_wstr(const std::string &src) {
    std::wstring ret(src.size(), L' ');
    ret.resize(std::mbstowcs(&ret[0], src.c_str(), src.size()));
    return ret;
}

inline std::string from_wstr(const std::wstring &src) {
    std::string ret(src.size() * sizeof(wchar_t), ' ');
    ret.resize(std::wcstombs(&ret[0], src.c_str(), ret.size()));
    return ret;
}

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_ENCODING_HPP
