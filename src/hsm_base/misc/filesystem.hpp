//
// Created by griha on 15.01.18.
//
#pragma once
#ifndef MIKRONSST_HSM_FILESYSTEM_HPP
#define MIKRONSST_HSM_FILESYSTEM_HPP

#include <string>
#include <windows.h>

#include <boost/filesystem.hpp>

namespace griha { namespace hsm {

namespace fs = boost::filesystem;

namespace {

std::wstring get_executable_path() {
    std::wstring ret(MAX_PATH, L'\0');
    GetModuleFileNameW(nullptr, &ret[0], MAX_PATH);

    return fs::path(ret).parent_path().native();
}

std::wstring get_executable_name() {
    std::wstring ret(MAX_PATH, L'\0');
    GetModuleFileNameW(nullptr, &ret[0], MAX_PATH);

    return fs::path(ret).filename().replace_extension("").native();
}

}

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_FILESYSTEM_HPP
