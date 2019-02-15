//
// Created by griha on 01.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_IERROR_HPP
#define MIKRONSST_HSM_IERROR_HPP

#include <windows.h>
#include <unknwn.h>

namespace griha { namespace hsm {

enum class ErrorCode : int {
    Success = 0,

    IncorrectArgument,
    CryptoError, // has additional information
    InternalError,
    RemoteError,
    InteropError
};

static const GUID IID_IError = {0xb8233cb8, 0x7319, 0x48e1, {0xac, 0x7e, 0x0e, 0xad, 0x09, 0x73, 0xff, 0xe3}};
struct IError : public virtual IUnknown {
    virtual HRESULT STDMETHODCALLTYPE setError(ErrorCode code, const wchar_t* message) = 0;
    virtual HRESULT STDMETHODCALLTYPE setError(ErrorCode code, const wchar_t* message, DWORD last_error) = 0;
};

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_IERROR_HPP
