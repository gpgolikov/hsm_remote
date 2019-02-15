//
// Created by griha on 07.01.18.
//
#pragma once
#ifndef MIKRONSST_HSM_ERROR_HPP
#define MIKRONSST_HSM_ERROR_HPP

#include <string>
#include <sstream>

#include <crypto/error.hpp>
#include <misc/io_manip.hpp>
#include <misc/unknown_based.hpp>

namespace griha { namespace hsm {

struct error_sink_type : public UnknownBasedFake<IError> {
    HRESULT STDMETHODCALLTYPE setError(ErrorCode code, const wchar_t* message) {
        this->code = code;
        this->message.assign(message);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE setError(ErrorCode code, const wchar_t* message, DWORD last_error) {
        this->code = code;

        std::wostringstream os;
        os << message << " " << get_last_error(last_error);
        this->message = os.str();
        return S_OK;
    }

    void clear() {
        code = ErrorCode::Success;
        message.clear();
    }

    ErrorCode code {ErrorCode::Success};
    std::wstring message;
};

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_ERROR_HPP
