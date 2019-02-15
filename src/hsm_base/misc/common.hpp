//
// Created by griha on 10.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_COMMON_HPP
#define MIKRONSST_HSM_COMMON_HPP

#include <string>

#include <crypto/error.hpp>
#include <crypto/input_output.hpp>

#include "encoding.hpp"
#include "logger.hpp"

namespace griha { namespace hsm {

inline void set_error(IError *error_sink, ErrorCode code, const std::string& message, DWORD last_error) {
    if (error_sink != nullptr) error_sink->setError(code, to_wstr(message).c_str(), last_error);
}

inline void set_error(IError *error_sink, ErrorCode code, const std::wstring& message, DWORD last_error) {
    if (error_sink != nullptr) error_sink->setError(code, message.c_str(), last_error);
}

inline void set_error(IError *error_sink, ErrorCode code, const std::string& message) {
    if (error_sink != nullptr) error_sink->setError(code, to_wstr(message).c_str());
}

inline void set_error(IError *error_sink, ErrorCode code, const std::wstring& message) {
    if (error_sink != nullptr) error_sink->setError(code, message.c_str());
}

template <typename _InIt>
HRESULT read_data(IInput *input, _InIt dest, DWORD &size, bool &more_avail, IError *error_sink) {
    LOG_DEBUG << "read_data: size " << size;

    HRESULT ret;
    long more_avail_ = 0;
    if ((ret = input->read(&dest[0], &size, &more_avail_)) != S_OK) {
        set_error(error_sink, ErrorCode::InteropError, "read_data: IInput::read has returned error");
        LOG_ERROR << "read_data: IInput::read has returned error " << std::hex << std::showbase << ret;
    }
    more_avail = more_avail_ != 0;

    if (more_avail && size == 0) {
        set_error(error_sink, ErrorCode::IncorrectArgument, "read_data: IInput::read has returned unexpected value");
        LOG_ERROR << "read_data: IInput::read has returned unexpected value";
        return E_UNEXPECTED;
    }

    LOG_DEBUG << "read_data: size (" << size << "); more data available ( " << std::boolalpha << more_avail << ")";

    return ret;
}

template <typename _OutIt>
HRESULT write_data(IOutput *output, _OutIt dest, DWORD size, IError *error_sink) {
    LOG_DEBUG << "write_data: size " << size;

    while (size) {
        DWORD sz = size;
        HRESULT res;
        if ((res = output->write(&dest[0], &sz)) != S_OK) {
            set_error(error_sink, ErrorCode::InteropError, "write_data: IOutput::write has returned error");
            LOG_ERROR << "write_data: IOutput::write has returned error " << std::hex << std::showbase << res;
            return res;
        }

        if (sz == 0) {
            set_error(error_sink, ErrorCode::IncorrectArgument, "write_data: unexpected behavior of IOutput::write");
            LOG_ERROR << "write_data: unexpected behavior of IOutput::write";
            return E_UNEXPECTED;
        }

        size -= sz;
        std::advance(dest, sz);

        LOG_DEBUG << "write_data: data written";
    }

    return S_OK;
}

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_COMMON_HPP
