//
// Created by griha on 13.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_CRYPTO_TYPES_HPP
#define MIKRONSST_HSM_CRYPTO_TYPES_HPP

#include <windows.h>
#include <wincrypt.h>

namespace griha { namespace hsm {

constexpr const wchar_t* PROVNAME_CRYPTOPRO_HSM = L"Crypto-Pro HSM CSP";
constexpr const wchar_t* PROVNAME_CRYPTOPRO_HSM_RSA = L"Crypto-Pro HSM RSA CSP";

enum prov_type : DWORD {
    PROV_CRYPTOPRO_HSM_RSA = PROV_RSA_FULL,
    PROV_CRYPTOPRO_HSM = 75
};

enum class ProvParam : DWORD {
    KeyExchangePin = PP_KEYEXCHANGE_PIN,
    SignaturePin = PP_SIGNATURE_PIN
};

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_CRYPTO_TYPES_HPP
