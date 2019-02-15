//
// Created by griha on 13.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_CRYPTO_WIN_BASE_HPP
#define MIKRONSST_HSM_CRYPTO_WIN_BASE_HPP

#include <functional>

#include <crypto/crypto_types.hpp>
#include <crypto/cipher.hpp>
#include <misc/io_manip.hpp>
#include <misc/common.hpp>
#include <misc/functional.hpp>

#include <griha/tools/guard.hpp>

namespace griha { namespace hsm { namespace tools {

using griha::tools::guard;

template<typename _InIter>
inline bool set_param(HCRYPTPROV h_prov, ProvParam param, _InIter b) {
    auto param_ = static_cast<DWORD>(param);
    if (!CryptSetProvParam(h_prov, param_, reinterpret_cast<const BYTE *>(&b[0]), 0)) {
        LOG_ERROR << "tools::set_param: error of setting provider param '" << param_ << "'" << last_error;
        return false;
    }

    return true;
}

template<typename _InIter>
inline bool set_param(HCRYPTKEY h_key, KeyParam param, _InIter b) {
    auto param_ = static_cast<DWORD>(param);
    if (!CryptSetKeyParam(h_key, param_, reinterpret_cast<const BYTE *>(&b[0]), 0)) {
        LOG_ERROR << "tools::set_param: error of setting key param '" << param_ << "'" << last_error;
        return false;
    }

    return true;
}

static bool get_user_key(HCRYPTPROV h_prov, bool signature, HCRYPTKEY &h_key) {
    HCRYPTKEY h_key_;
    if (!CryptGetUserKey(h_prov, signature ? AT_SIGNATURE : AT_KEYEXCHANGE, &h_key_)) {
        LOG_ERROR << "CryptoContext::get_user_key: error when user key has been requested " << last_error;
        return false;
    }
    auto h_key_guard = guard(h_key_, safed_deleter(CryptDestroyKey));

    if (!CryptDuplicateKey(h_key_, nullptr, 0, &h_key)) {
        LOG_ERROR << "CryptoContext::get_user_key: error while user key has been being duplicated "
                  << last_error;
        return false;
    }

    return true;
}

template<typename _InIter>
static bool import_user_key(const std::wstring &cont_name, const std::wstring &prov_name, DWORD prov_type,
                            _InIter blob, DWORD blob_n) {
    HCRYPTPROV h_prov {0};
    if (CryptAcquireContext(&h_prov, cont_name.c_str(), prov_name.c_str(), prov_type, 0)) {
        CryptReleaseContext(h_prov, 0);
        LOG_ERROR << "import_user_key: already created container";
        return false;
    }

    if (NTE_BAD_KEYSET != GetLastError() ||
        !CryptAcquireContext(&h_prov, cont_name.c_str(), prov_name.c_str(), prov_type,
                             CRYPT_NEWKEYSET)) {
        LOG_ERROR << "import_user_key: error when crypto context has been acquired "
                  << last_error;
        return false;

    }

    auto h_prov_guard = guard(h_prov, safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0)));

    HCRYPTKEY h_key {0};
    if (!CryptImportKey(h_prov, &blob[0], blob_n, 0, CRYPT_EXPORTABLE, &h_key)) {
        LOG_ERROR << "import_user_key: error while key blob has being been imported "
                  << last_error;
        return false;
    }
    safed_deleter(CryptDestroyKey)(h_key);

    return true;
}

template<typename _Cont>
static bool export_user_key(HCRYPTPROV h_key, HCRYPTKEY h_key_trans, bool pub_key, _Cont &dst) {
    DWORD sz = 0;
    // get blob size
    if (!CryptExportKey(h_key, h_key_trans, pub_key ? PUBLICKEYBLOB : PRIVATEKEYBLOB, 0, nullptr, &sz)) {
        LOG_ERROR << "export_user_key: error in CryptExportKey when buffer size has been required "
                  << last_error;
        return false;
    }

    dst.resize(sz, 0);
    // get blob
    if (!CryptExportKey(h_key, h_key_trans, pub_key ? PUBLICKEYBLOB : PRIVATEKEYBLOB, 0, dst.data(), &sz)) {
        LOG_ERROR << "CryptoContext::export_user_key: error in CryptExportKey while key has been being exported "
                  << last_error;
        return false;
    }

    LOG_DEBUG << "CryptoContext::export_user_key: exported size " << sz << "; destination size " << dst.size();

    return true;
}

static bool gen_user_key(const std::wstring &cont_name, const std::wstring &prov_name, DWORD prov_type) {

    HCRYPTPROV h_prov {0};
    if (CryptAcquireContext(&h_prov, cont_name.c_str(), prov_name.c_str(), prov_type, 0)) {
        CryptReleaseContext(h_prov, 0);
        LOG_ERROR << "CryptoContext::get_user_key: already created container";
        return false;
    }

    if (NTE_BAD_KEYSET != GetLastError() ||
        !CryptAcquireContext(&h_prov, cont_name.c_str(), prov_name.c_str(), prov_type,
                             CRYPT_NEWKEYSET)) {
        LOG_ERROR << "CryptoContext::gen_user_key: error when crypto context has been acquired "
                  << last_error;
        return false;
    }
    auto h_prov_guard = guard(h_prov, safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0)));

    HCRYPTKEY h_key {0};
    if (!CryptGenKey(h_prov, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &h_key)) {
        LOG_ERROR << "CryptoContext::gen_user_key: error while key blob has being been generated "
                  << last_error;
        return false;
    }
    safed_deleter(CryptDestroyKey)(h_key);

    h_key = 0;
    if (!CryptGenKey(h_prov, AT_SIGNATURE, CRYPT_EXPORTABLE, &h_key)) {
        LOG_ERROR << "CryptoContext::gen_user_key: error while key blob has being been generated "
                  << last_error;
        return false;
    }
    safed_deleter(CryptDestroyKey)(h_key);

    return true;
}

static bool remove_user_key(const std::wstring &cont_name, const std::wstring &prov_name, DWORD prov_type) {

    HCRYPTPROV h_prov {0};
    if (!CryptAcquireContext(&h_prov, cont_name.c_str(), prov_name.c_str(), prov_type, CRYPT_DELETE_KEYSET)) {
        LOG_ERROR << "remove_user_key: error while key container has being been clean "
                  << last_error;
        return false;
    }
    return true;
}

}}} // namespace griha::hsm::tools

#endif //MIKRONSST_HSM_CRYPTO_WIN_BASE_HPP
