//
// Created by griha on 08.12.17.
//
#include <cassert>
#include <vector>
#include <array>

#include <cryptopp/rsa.h>

#include <griha/tools/guard.hpp>

#include <misc/unknown_based.hpp>
#include <misc/logger.hpp>
#include <misc/functional.hpp>

#include "crypto/hsm_lib/cipher.hpp"
#include "crypto_context_impl.hpp"
#include "crypto_win_base.hpp"
#include "keys.hpp"

namespace griha { namespace hsm {

using griha::tools::guard;

using tools::set_param;

struct RsaCipher : public UnknownBased<IRsaCipher> {
    using super_type = UnknownBased<IRsaCipher>;

    RsaCipher() : super_type(IID_IRsaCipher, IID_ICipher) {}
    ~RsaCipher() {
        if (h_key)
            safed_deleter(CryptDestroyKey)(h_key);
        if (h_key_trans)
            safed_deleter(CryptDestroyKey)(h_key_trans);
        LOG_DEBUG << "RsaCipher::dstr: cipher destroyed";
    }

    bool initialize(CryptoContext *context);

    HRESULT STDMETHODCALLTYPE Decrypt(IInput *in, IOutput *out, IError *error_sink);
    HRESULT STDMETHODCALLTYPE Encrypt(IInput *in, IOutput *out, IError *error_sink);

    HRESULT STDMETHODCALLTYPE TrapdoorPub(IInput *in, IOutput *out, IError *err_sink);
    HRESULT STDMETHODCALLTYPE TrapdoorPri(IInput *in, IOutput *out, IError *err_sink);

    HCRYPTKEY h_key {0}, h_key_trans {0};
    public_key_type pub_key;
    private_key_type pri_key;
};

bool RsaCipher::initialize(CryptoContext *context) {
    assert(context != nullptr);

    if (!CryptDuplicateKey(context->h_key_exchange, nullptr, 0, &h_key)) {
        LOG_ERROR << "SymmCipher::initialize: error while user exchange key has being been duplicated"
                  << last_error;
        return false;
    }

    h_key_trans = context->h_key_trans;
    if (context->h_key_trans &&
            !CryptDuplicateKey(context->h_key_trans, nullptr, 0, &h_key_trans)) {
        LOG_ERROR << "SymmCipher::initialize: error while user exchange key has being been duplicated"
                  << last_error;
        return false;
    }

    return pub_key.initialize(h_key) && pri_key.initialize(pub_key, h_key_trans);
}

HRESULT STDMETHODCALLTYPE RsaCipher::Decrypt(IInput *in, IOutput *out, IError *error_sink) {
    if (in == nullptr || out == nullptr) {
        set_error(error_sink, ErrorCode::IncorrectArgument,
                  "RsaCipher::Decrypt: input and output streams should be specified");
        LOG_ERROR << "RsaCipher::Decrypt: input and output streams should be specified";
        return E_INVALIDARG;
    }

    try {
        std::vector<uint8_t> buffer;
        buffer.resize(pub_key.key_size / 8, 0);
        DWORD sz;
        HRESULT res;
        bool more_data;
        do {
            sz = buffer.size();
            if ((res = read_data(in, buffer.begin(), sz, more_data, error_sink)) != S_OK)
                return res;

            if (sz != buffer.size()) {
                set_error(error_sink, ErrorCode::InternalError, "RsaCipher::Decrypt: incorrect data size");
                LOG_ERROR << "RsaCipher::Decrypt: incorrect data size";
                return E_UNEXPECTED;
            }

            if (!CryptDecrypt(h_key, 0, true, 0, buffer.data(), &sz)) {
                set_error(error_sink, ErrorCode::CryptoError,
                          "RsaCipher::Decrypt: error while data has being been decrypted", GetLastError());
                LOG_ERROR << "RsaCipher::Decrypt: error while data has being been decrypted"
                          << last_error;
                return E_FAIL;
            }

            if ((res = write_data(out, buffer.begin(), sz, error_sink)) != S_OK)
                return res;

        } while (more_data);

        LOG_DEBUG << "RsaCipher::Decrypt: decryption has successfully been completed";
        return S_OK;

    } catch (std::exception &e) {
        set_error(error_sink, ErrorCode::InternalError, "RsaCipher::Decrypt: decryption has been failed");
        LOG_CRITICAL << "RsaCipher::Decrypt: decryption has been failed with error: " << e.what();
    } catch (...) {
        set_error(error_sink, ErrorCode::InternalError, "RsaCipher::Decrypt: decryption has been failed");
        LOG_CRITICAL << "RsaCipher::Decrypt: decryption has been failed with unknown error";
    }

    return E_FAIL;
}

HRESULT STDMETHODCALLTYPE RsaCipher::Encrypt(IInput *in, IOutput *out, IError *error_sink) {
    if (in == nullptr || out == nullptr) {
        set_error(error_sink, ErrorCode::IncorrectArgument,
                  "RsaCipher::Encrypt: input and output streams should be specified");
        LOG_ERROR << "RsaCipher::Encrypt: input and output streams should be specified";
        return E_INVALIDARG;
    }

    try {
        std::vector<uint8_t> buffer;
        buffer.resize(pub_key.key_size / 8, 0);
        const size_t block_size = buffer.size() - 11; /* PKCS1 v1.5 minimum header size */
        DWORD sz;
        HRESULT res;
        bool more_data;
        do {
            sz = block_size;
            if ((res = read_data(in, buffer.begin(), sz, more_data, error_sink)) != S_OK)
                return res;

//            if (sz > block_size) {
//                set_error(error_sink, ErrorCode::InternalError, "RsaCipher::Encrypt: incorrect data size");
//                LOG_ERROR << "RsaCipher::Encrypt: incorrect data size";
//                return E_UNEXPECTED;
//            }

            if (!CryptEncrypt(h_key, 0, true, 0, buffer.data(), &sz, buffer.size())) {
                set_error(error_sink, ErrorCode::CryptoError,
                          "RsaCipher::Encrypt: error while data has being been encrypted", GetLastError());
                LOG_ERROR << "RsaCipher::Encrypt: error while data has being been encrypted"
                          << last_error;
                return E_FAIL;
            }

            if ((res = write_data(out, buffer.begin(), sz, error_sink) != S_OK))
                return res;
        } while (more_data);

        LOG_DEBUG << "RsaCipher::Encrypt: encryption has successfully been completed";
        return S_OK;

    } catch (std::exception &e) {
        set_error(error_sink, ErrorCode::InternalError, "RsaCipher::Encrypt: encryption has been failed");
        LOG_CRITICAL << "RsaCipher::Encrypt: encryption has been failed with error: " << e.what();
    } catch (...) {
        set_error(error_sink, ErrorCode::InternalError, "RsaCipher::Encrypt: encryption has been failed");
        LOG_CRITICAL << "RsaCipher::Encrypt: encryption has been failed with unknown error";
    }

    return E_FAIL;
}

//using CryptoPP::Integer;

template <typename KeyT>
HRESULT trapdoor_rsa(const KeyT &key, IInput *in, IOutput *out, IError *error_sink) {
    assert(in != nullptr && out != nullptr);

    try {
        CryptoPP::SecBlock<uint8_t>
                n {key.key_size / 8}, // modulus
                e {key.exp_size / 8}; // private or public exponent

        if (!key.get_key(n.begin(), e.begin())) {
            LOG_ERROR << "trapdoor_rsa: key is not available";
            return E_UNEXPECTED;
        }

        CryptoPP::RSAFunction rsa;
        rsa.Initialize({n.data(), n.size()}, {e.data(), e.size()});

        std::vector<uint8_t> buffer;
        buffer.resize(key.key_size / 8, 0);
        DWORD sz;
        HRESULT res;
        bool more_data;
        do {
            sz = buffer.size();
            if ((res = read_data(in, buffer.begin(), sz, more_data, error_sink)) != S_OK)
                return res;

//            if (sz != buffer.size()) {
//                set_error(error_sink, ErrorCode::InternalError, "trapdoor_rsa: incorrect data size");
//                LOG_ERROR << "trapdoor_rsa: incorrect data size";
//                return E_UNEXPECTED;
//            }

            CryptoPP::Integer x(buffer.data(), sz); // data in big-endian format is assumed
            x = rsa.ApplyFunction(x);

            sz = x.ByteCount();
            x.Encode(buffer.data(), sz);

            if ((res = write_data(out, buffer.begin(), sz, error_sink)) != S_OK)
                return res;
        } while(more_data);

        LOG_DEBUG << "trapdoor_rsa: trapdoor permutation has successfully been completed";
        return S_OK;

    } catch (CryptoPP::Exception &e) {
        set_error(error_sink, ErrorCode::CryptoError, "trapdoor_rsa: process has been failed");
        LOG_CRITICAL << "trapdoor_rsa: process has been failed with error: type "
                     << e.GetErrorType() << "; message " << e.GetWhat();
    } catch (std::exception &e) {
        set_error(error_sink, ErrorCode::InternalError, "trapdoor_rsa: process has been failed");
        LOG_CRITICAL << "trapdoor_rsa: process has been failed with error: " << e.what();
    } catch (...) {
        set_error(error_sink, ErrorCode::InternalError, "trapdoor_rsa: process has been failed");
        LOG_CRITICAL << "trapdoor_rsa: process has been failed with unknown error";
    }

    return E_FAIL;
}

HRESULT STDMETHODCALLTYPE RsaCipher::TrapdoorPub(IInput *in, IOutput *out, IError *error_sink) {
    if (in == nullptr || out == nullptr) {
        set_error(error_sink, ErrorCode::IncorrectArgument,
                  "RsaCipher::TrapdoorPub: input and output streams should be specified");
        LOG_ERROR << "RsaCipher::TrapdoorPub: input and output streams should be specified";
        return E_INVALIDARG;
    }

    LOG_DEBUG << "RsaCipher::TrapdoorPub has been called";
    return trapdoor_rsa(pub_key, in, out, error_sink);
}

HRESULT STDMETHODCALLTYPE RsaCipher::TrapdoorPri(IInput *in, IOutput *out, IError *error_sink) {
    if (in == nullptr || out == nullptr) {
        set_error(error_sink, ErrorCode::IncorrectArgument,
                  "RsaCipher::TrapdoorPri: input and output streams should be specified");
        LOG_ERROR << "RsaCipher::TrapdoorPri: input and output streams should be specified";
        return E_INVALIDARG;
    }

    LOG_DEBUG << "RsaCipher::TrapdoorPri has been called";
    return trapdoor_rsa(pri_key, in, out, error_sink);
}

//======================

struct SymmCipher : public UnknownBased<ICipher> {
    using super_type = UnknownBased<ICipher>;

    SymmCipher() : super_type(IID_ICipher) {}
    ~SymmCipher() {
        if (h_key)
            safed_deleter(CryptDestroyKey)(h_key);
    }

    bool initialize(CryptoContext *context, CipherMode mode, Padding padding);

    HRESULT STDMETHODCALLTYPE Decrypt(IInput *in, IOutput *out, IError *error_sink);
    HRESULT STDMETHODCALLTYPE Encrypt(IInput *in, IOutput *out, IError *error_sink);

    HCRYPTKEY h_key {0};
    CipherMode mode;
    Padding padding;
};

bool SymmCipher::initialize(CryptoContext *context, CipherMode mode, Padding padding) {
    assert(context != nullptr);

    bool ret = true;
    if (!CryptDuplicateKey(context->h_key_exchange, nullptr, 0, &h_key)) {
        LOG_ERROR << "SymmCipher::initialize: error while user exchange key has being been duplicated"
                  << last_error;
        ret = false;

        LOG_INFO << "SymmCipher::initialize: try to get user signature key for exchanging";
    }
    if (!ret && !CryptDuplicateKey(context->h_key_signature, nullptr, 0, &h_key)) {// ???? - cryptopro huck
        LOG_ERROR << "SymmCipher::initialize: error while user signature key has being been duplicated for exchange"
                  << last_error;
        return false;
    }

    if (!set_param(h_key, KeyParam::Mode, reinterpret_cast<DWORD*>(&mode)) ||
        !set_param(h_key, KeyParam::Padding, reinterpret_cast<DWORD*>(&padding)))
        return false;

    this->mode = mode;
    this->padding = padding;

    return true;
}

HRESULT STDMETHODCALLTYPE SymmCipher::Decrypt(IInput *in, IOutput *out, IError *error_sink) {
    if (in == nullptr || out == nullptr) {
        set_error(error_sink, ErrorCode::IncorrectArgument,
                  "SymmCipher::Decrypt: input and output streams should be specified");
        LOG_ERROR << "SymmCipher::Decrypt: input and output streams should be specified";
        return E_INVALIDARG;
    }

    static const DWORD BLOCK_SIZE = 2048;

    try {
        std::array<uint8_t, BLOCK_SIZE> buffer = {0};
        DWORD sz;
        HRESULT res;
        bool more_data;
        do {
            sz = BLOCK_SIZE;
            if ((res = read_data(in, buffer.begin(), sz, more_data, error_sink)) != S_OK)
                return res;

            if (!CryptDecrypt(h_key, 0, !more_data, 0, buffer.data(), &sz)) {
                set_error(error_sink, ErrorCode::CryptoError,
                          "SymmCipher::Decrypt: error while data has being been decrypted", GetLastError());
                LOG_ERROR << "SymmCipher::Decrypt: error while data has being been decrypted"
                          << last_error;
                return E_FAIL;
            }

            if ((res = write_data(out, buffer.begin(), sz, error_sink)) != S_OK)
                return res;

        } while (more_data);

        LOG_DEBUG << "SymmCipher::Decrypt: decryption has successfully been completed";
        return S_OK;

    } catch (std::exception &e) {
        set_error(error_sink, ErrorCode::InternalError, "SymmCipher::Decrypt: decryption has been failed");
        LOG_CRITICAL << "SymmCipher::Decrypt: decryption has been failed with error: " << e.what();
    } catch (...) {
        set_error(error_sink, ErrorCode::InternalError, "SymmCipher::Decrypt: decryption has been failed");
        LOG_CRITICAL << "SymmCipher::Decrypt: decryption has been failed with unknown error";
    }

    return E_FAIL;
}

HRESULT STDMETHODCALLTYPE SymmCipher::Encrypt(IInput *in, IOutput *out, IError *error_sink) {
    if (in == nullptr || out == nullptr) {
        set_error(error_sink, ErrorCode::IncorrectArgument,
                  "SymmCipher::Encrypt: input and output streams should be specified");
        LOG_ERROR << "SymmCipher::Encrypt: input and output streams should be specified";
        return E_INVALIDARG;
    }

    static const DWORD BLOCK_SIZE = 2048;

    try {
        std::array<uint8_t, BLOCK_SIZE + 64> buffer = {0};
        DWORD sz;
        HRESULT res;
        bool more_data;
        do {
            sz = BLOCK_SIZE;
            if ((res = read_data(in, buffer.begin(), sz, more_data, error_sink)) != S_OK)
                return res;

            if (!CryptEncrypt(h_key, 0, !more_data, 0, buffer.data(), &sz, buffer.size())) {
                set_error(error_sink, ErrorCode::CryptoError,
                          "SymmCipher::Encrypt: error while data has being been encrypted", GetLastError());
                LOG_ERROR << "SymmCipher::Encrypt: error while data has being been encrypted"
                          << last_error;
                return E_FAIL;
            }

            if ((res = write_data(out, buffer.begin(), sz, error_sink)) != S_OK)
                return res;

        } while (more_data);

        LOG_DEBUG << "SymmCipher::Encrypt: encryption has successfully been completed";
        return S_OK;

    } catch (std::exception &e) {
        set_error(error_sink, ErrorCode::InternalError, "SymmCipher::Encrypt: encryption has been failed");
        LOG_CRITICAL << "SymmCipher::Encrypt: encryption has been failed with error: " << e.what();
    } catch (...) {
        set_error(error_sink, ErrorCode::InternalError, "SymmCipher::Encrypt: encryption has been failed");
        LOG_CRITICAL << "SymmCipher::Encrypt: encryption has been failed with unknown error";
    }

    return E_FAIL;
}

//======================

IRsaCipher* __cdecl CreateRsaCipher(ICryptoContext *context, IError *error_sink) {
    auto context_ = dynamic_cast<CryptoContext*>(context);
    if (context_ == nullptr) {
        set_error(error_sink, ErrorCode::IncorrectArgument,
                  "CreateRsaCipher: context should be specified and created by CreateCryptoContext function");
        LOG_ERROR << "CreateRsaCipher: context should be specified and created by CreateCryptoContext function";
        return nullptr;
    }

    try {
        ALG_ID algo; DWORD size = sizeof(ALG_ID);
        if (!CryptGetKeyParam(context_->h_key_exchange, KP_ALGID, reinterpret_cast<BYTE*>(&algo), &size, 0)) {
            set_error(error_sink, ErrorCode::CryptoError,
                      "CreateRsaCipher: context should be specified and created by CreateCryptoContext function",
                      GetLastError());
            LOG_ERROR << "CreateRsaCipher: error when KP_ALGID has been requested: " << last_error;
            return nullptr;
        }

        if (GET_ALG_TYPE(algo) != ALG_TYPE_RSA) {
            set_error(error_sink, ErrorCode::CryptoError, "CreateRsaCipher: unsupported algorithm");
            LOG_ERROR << "CreateRsaCipher: unsupported algorithm: " << std::hex << std::showbase << algo;
            return nullptr;
        }

        auto ret = guard(new RsaCipher);
        if (!ret->initialize(context_)) {
            set_error(error_sink, ErrorCode::CryptoError,
                      "CreateRsaCipher: error while preparing user exchange key", GetLastError());
            return nullptr;
        }

        LOG_INFO << "CreateRsaCipher: RSA cipher has successfully been created";
        return ret.release();

    } catch (std::exception &e) {
        LOG_CRITICAL << "CreateRsaCipher: cipher creating has been failed with error: " << e.what();
        set_error(error_sink, ErrorCode::InternalError, "CreateRsaCipher: cipher creating has been failed");
    } catch (...) {
        set_error(error_sink, ErrorCode::InternalError, "CreateRsaCipher: cipher creating has been failed");
        LOG_CRITICAL << "CreateRsaCipher: cipher creating has been failed with unknown error";
    }

    return nullptr;
}

ICipher* __cdecl CreateCipher(ICryptoContext *context, CipherMode mode, Padding padding, IError *error_sink) {

    auto context_ = dynamic_cast<CryptoContext*>(context);
    if (context_ == nullptr) {
        set_error(error_sink, ErrorCode::IncorrectArgument,
                  "CreateRsaCipher: context should be specified and created by CreateCryptoContext function");
        LOG_ERROR << "CreateRsaCipher: context should be specified and created by CreateCryptoContext function";
        return nullptr;
    }

    try {
        auto ret = guard(new SymmCipher);
        if (!ret->initialize(context_, mode, padding)) {
            set_error(error_sink, ErrorCode::CryptoError,
                      "CreateRsaCipher: error while preparing user exchange key", GetLastError());
            return nullptr;
        }

        LOG_INFO << "CreateRsaCipher: symmetric cipher has successfully been created";
        return ret.release();

    } catch (std::exception &e) {
        set_error(error_sink, ErrorCode::InternalError, "CreateRsaCipher: cipher creating has been failed");
        LOG_CRITICAL << "CreateRsaCipher: cipher creating has been failed with error: " << e.what();
    } catch (...) {
        set_error(error_sink, ErrorCode::InternalError, "CreateRsaCipher: cipher creating has been failed");
        LOG_CRITICAL << "CreateRsaCipher: cipher creating has been failed with unknown error";
    }

    return nullptr;
}

}} // namespace griha::hsm