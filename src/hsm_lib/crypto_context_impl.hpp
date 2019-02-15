//
// Created by griha on 13.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_CRYPTO_CONTEX_IMPL_HPP
#define MIKRONSST_HSM_CRYPTO_CONTEX_IMPL_HPP

#include <crypto/crypto_context.hpp>
#include <misc/unknown_based.hpp>

#include "crypto_win_base.hpp"

namespace griha { namespace hsm {

struct CryptoContext : public UnknownBased<ICryptoContext> {
    using super_type = UnknownBased<ICryptoContext>;

    CryptoContext() : super_type(IID_ICryptoContext) {}
    ~CryptoContext();

    bool initialize(const wchar_t *prov_name, DWORD prov_type, const wchar_t *cont_name,
                        const wchar_t *trans_cont_name, bool silent, bool trans_silent);

    HCRYPTPROV h_prov {0}, h_prov_trans {0};
    HCRYPTKEY h_key_exchange {0}, h_key_signature {0}, h_key_trans {0};

};

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_CRYPTO_CONTEX_IMPL_HPP
