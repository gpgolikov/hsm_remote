//
// Created by griha on 16.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_TEST_COMMON_HPP
#define MIKRONSST_HSM_TEST_COMMON_HPP

#include <vector>

#include <windows.h>

#include <crypto/error.hpp>
#include <misc/unknown_based.hpp>

namespace griha { namespace hsm {

static const wchar_t *CONT_NAME = L"test_griha0001";
static const wchar_t *CONT_NAME_TRANS = L"test_griha_trans0001";
static const char *CONT_PSWD = "12345678";

struct Error : public UnknownBasedFake<IError> {
    HRESULT STDMETHODCALLTYPE setError(ErrorCode code, const wchar_t *message) {
        this->code = code;
        this->message = message;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE setError(ErrorCode code, const wchar_t *message, DWORD last_error) {
        this->code = code;
        this->message = message;
        this->last_error = last_error;
        return S_OK;
    }

    ErrorCode code{ErrorCode::Success};
    std::wstring message{L"No error"};
    DWORD last_error{NO_ERROR};

    void clear() {
        code = ErrorCode::Success;
        message = L"No error";
        last_error = NO_ERROR;
    }
};

struct Input : public UnknownBasedFake<IInput> {
    HRESULT STDMETHODCALLTYPE read(BYTE *buffer, DWORD *size, long *more_data) {
        uint32_t l = data.size() - offset;
        l = *size < l ? *size : l;
        std::copy_n(data.begin() + offset, l, buffer);
        offset += l;
        *size = l;
        *more_data = (offset < data.size()) ? 1 : 0;
        return S_OK;
    }

    std::vector<uint8_t> data;
    uint32_t offset {0};
};

struct Output : public UnknownBasedFake<IOutput> {
    HRESULT STDMETHODCALLTYPE write(const BYTE *data, DWORD *size) {
        this->data.insert(this->data.end(), data, data + *size);
        return S_OK;
    }

    std::vector<uint8_t> data;
};

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_TEST_COMMON_HPP
