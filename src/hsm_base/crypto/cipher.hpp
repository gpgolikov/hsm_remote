//
// Created by griha on 01.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_IDECRYPTER_H
#define MIKRONSST_HSM_IDECRYPTER_H

#include <windows.h>
#include <wincrypt.h>
#include <unknwn.h>

#include "error.hpp"
#include "crypto_context.hpp"
#include "input_output.hpp"

namespace griha { namespace hsm {

enum class KeyParam : DWORD {
    Mode = KP_MODE,
    Padding = KP_PADDING
};

enum class CipherMode : DWORD {
    ECB = CRYPT_MODE_ECB,
    CBC = CRYPT_MODE_CBC,
    CFB = CRYPT_MODE_CFB,
    OFB = CRYPT_MODE_OFB,
    CTS = CRYPT_MODE_CTS
};

enum class Padding : DWORD {
    Pkcs5 = PKCS5_PADDING,
    Random = RANDOM_PADDING,
    Zero = ZERO_PADDING
};

static const GUID IID_ICipher = { 0x2465d915, 0xd66a, 0x497d, {0xb9, 0x0e, 0xc2, 0xae, 0xc2, 0xfb, 0x77, 0x4b} };
struct ICipher : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Decrypt(IInput *in, IOutput *out, IError *error_sink) = 0;
    virtual HRESULT STDMETHODCALLTYPE Encrypt(IInput *in, IOutput *out, IError *error_sink) = 0;
};

static const GUID IID_IRsaCipher = { 0x1a20e261, 0x1b77, 0x45de, {0xa4, 0xf6, 0x34, 0x62, 0x5a, 0x5b, 0xcb, 0x67} };
struct IRsaCipher : public ICipher {
    virtual HRESULT STDMETHODCALLTYPE TrapdoorPub(IInput *in, IOutput *out, IError *err_sink) = 0;
    virtual HRESULT STDMETHODCALLTYPE TrapdoorPri(IInput *in, IOutput *out, IError *err_sink) = 0;
};

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_IDECRYPTER_H
