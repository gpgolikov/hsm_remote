//
// Created by griha on 13.01.18.
//
#pragma once
#ifndef MIKRONSST_HSM_CLIENT_CIPHER_HPP
#define MIKRONSST_HSM_CLIENT_CIPHER_HPP

#include <crypto/cipher.hpp>
#include <crypto/crypto_context.hpp>
#include <crypto/error.hpp>

namespace griha { namespace hsm {

extern "C" {

__declspec(dllexport) ICipher* __cdecl CreateCipher(ICryptoContext *context, IError *error_sink);
__declspec(dllexport) IRsaCipher* __cdecl CreateRsaCipher(ICryptoContext *context, IError *error_sink);

}

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_CLIENT_CIPHER_HPP
