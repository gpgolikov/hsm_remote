//
// Created by griha on 13.01.18.
//
#pragma once
#ifndef MIKRONSST_HSM_LIB_CRYPTO_CONTEXT_HPP
#define MIKRONSST_HSM_LIB_CRYPTO_CONTEXT_HPP

#include <crypto/crypto_context.hpp>
#include <crypto/error.hpp>

namespace griha { namespace hsm {

extern "C" {

__declspec(dllexport) ICryptoContext *
__cdecl CreateCryptoContext(const wchar_t *prov_name, DWORD prov_type,
                            const wchar_t *cont_name, const char *password,
                            const wchar_t *trans_cont_name, const char *trans_password,
                            IError *error_sink);
}

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_LIB_CRYPTO_CONTEXT_HPP
