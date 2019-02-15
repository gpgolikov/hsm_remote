//
// Created by griha on 10.12.17.
//
#include <cassert>

#include <griha/tools/guard.hpp>

#include <misc/logger.hpp>
#include <misc/io_manip.hpp>

#include "crypto_context_impl.hpp"
#include "crypto/hsm_lib/crypto_context.hpp"
#include "misc/common.hpp"

namespace griha { namespace hsm {

using griha::tools::guard;

using tools::get_user_key;
using tools::set_param;

CryptoContext::~CryptoContext() {
    if (h_key_exchange)
        safed_deleter(CryptDestroyKey)(h_key_exchange);
    if (h_key_signature)
        safed_deleter(CryptDestroyKey)(h_key_signature);
    if (h_key_trans)
        safed_deleter(CryptDestroyKey)(h_key_trans);
    if (h_prov)
        safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0))(h_prov);
    if (h_prov_trans)
        safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0))(h_prov_trans);
}

bool CryptoContext::initialize(const wchar_t *prov_name, DWORD prov_type,
                               const wchar_t *cont_name, const wchar_t *trans_cont_name,
                               bool silent, bool trans_silent) {
    assert(cont_name != nullptr);

    if (!CryptAcquireContext(&h_prov, cont_name, prov_name, prov_type, silent ? CRYPT_SILENT : 0)) {
        LOG_ERROR << "CryptoContext::initialize: error when crypto context has been acquired " << last_error;
        return false;
    }

    LOG_DEBUG << "CryptoContext::initialize: user exchange key request";
    bool ret = get_user_key(h_prov, false, h_key_exchange);
    LOG_DEBUG << "CryptoContext::initialize: user signature key request";
    ret = get_user_key(h_prov, true, h_key_signature) || ret;

    if (!trans_cont_name)
        return ret;

    if (!CryptAcquireContext(&h_prov_trans, trans_cont_name, prov_name, prov_type, trans_silent ? CRYPT_SILENT : 0)) {
        LOG_ERROR << "CryptoContext::initialize: error when crypto context of the transport container has been acquired "
                  << last_error;
        return false;
    }

    LOG_DEBUG << "CryptoContext::initialize: transport key request";
    return get_user_key(h_prov_trans, false, h_key_trans) || get_user_key(h_prov_trans, true, h_key_trans);
}

ICryptoContext* __cdecl CreateCryptoContext(const wchar_t *prov_name, DWORD prov_type,
                                    const wchar_t *cont_name, const char *password,
                                    const wchar_t *trans_cont_name, const char *trans_password,
                                    IError *error_sink) {
    if (cont_name == nullptr) {
        LOG_ERROR << "CreateCryptoContext: container name should be set";
        set_error(error_sink, ErrorCode::IncorrectArgument, "CreateCryptoContext: container name should be set");
        return nullptr;
    }

    try {
        auto ret = guard(new CryptoContext);
        if (!ret->initialize(prov_name, prov_type, cont_name, trans_cont_name, password != nullptr,
                             trans_password != nullptr)) {
            set_error(error_sink, ErrorCode::CryptoError,
                      "CreateCryptoContext: crypto context initialization has been failed", GetLastError());
            return nullptr;
        }

        if (password != nullptr &&
            (!set_param(ret->h_prov, ProvParam::KeyExchangePin, password) &&
             !set_param(ret->h_prov, ProvParam::SignaturePin, password))) {
            set_error(error_sink, ErrorCode::IncorrectArgument,
                      "CreateCryptoContext: error of setting user key password", GetLastError());
            return nullptr;
        }

        if (ret->h_key_trans && trans_password != nullptr &&
            !set_param(ret->h_prov_trans, ProvParam::KeyExchangePin, trans_password)) {
            set_error(error_sink, ErrorCode::IncorrectArgument,
                      "CreateCryptoContext: error of setting transport key password", GetLastError());
            return nullptr;
        }

        LOG_INFO << "CreateCryptoContext: crypto context has successfully been created";
        return ret.release();

    } catch (std::exception &e) {
        set_error(error_sink, ErrorCode::InternalError, "CreateCryptoContext: crypto context creating has been failed");
        LOG_CRITICAL << "CreateCryptoContext: crypto context creating has been failed with error: " << e.what();
    } catch (...) {
        set_error(error_sink, ErrorCode::InternalError, "CreateCryptoContext: crypto context creating has been failed");
        LOG_CRITICAL << "CreateCryptoContext: crypto context creating has been failed with unknown error";
    }

    return nullptr;
}

}} // namespace griha::hsm