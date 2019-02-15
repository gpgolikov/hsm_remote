//
// Created by griha on 13.01.18.
//
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>

#include <misc/unknown_based.hpp>
#include <misc/common.hpp>
#include <misc/logger.hpp>

#include <griha/tools/guard.hpp>
#include <griha/tools/hexadecimal.hpp>

#include "crypto/hsm_client/cipher.hpp"
#include "crypto/hsm_client/crypto_context.hpp"

namespace griha { namespace hsm {

namespace asio = boost::asio;
namespace ip = boost::asio::ip;

using asio::ip::tcp;
using boost::system::error_code;

using namespace griha::tools;

typedef std::vector<uint8_t> data_type;

struct client_type {
    enum { PING = 1, CREATE_CRYPTO_CONTEXT, CREATE_CIPHER, DECRYPT, ENCRYPT, TRAPDOOR_PUB, TRAPDOOR_PRI };
    enum { SUCCESS = 0, ERR_INCORRECT_COMMAND, ERR_BAD_DATA, ERR_NOT_INITIALIZED, ERR_BAD_KEY_ID, ERR_INTERNAL,
        ERR_CRYPTO_CONTEXT_ALREADY_CREATED, ERR_CIPHER, ERR_UNKNOWN };
	
#pragma pack(push)
#pragma pack(1)
    struct header_type {
        uint8_t cmd {0};
        uint8_t qual {0};
        uint16_t len {0};
    };

    struct create_crypto_context_data_type {
        uint16_t key_id {0};
    };

    struct create_cipher_data_type {};
#pragma pack(pop)

    client_type() : service(), socket(service) {}

    ~client_type() {
        try {
            if (socket.is_open())
                socket.close();
        } catch(std::exception &e) {
            LOG_CRITICAL << "client_type::dstr: error while client has being been destroyed: " << e.what();
        } catch(...) {
            LOG_CRITICAL << "client_type::dstr: error while client has being been destroyed";
        }
        LOG_INFO << "client has been destroyed";
    }

    template <typename _InIt> header_type send(header_type hdr, _InIt data);
    template <typename _InIt, typename _OutCont> header_type send(header_type hdr, _InIt data, _OutCont &resp_data);

    template <typename _DataT> header_type send_n(header_type hdr, _DataT &&data, size_t size = sizeof(_DataT));

    asio::io_service service;
    tcp::socket socket;
};

struct crypto_context_type : public UnknownBased<ICryptoContext> {
    using super_type = UnknownBased<ICryptoContext>;

    client_type client;

    crypto_context_type() : super_type(IID_ICryptoContext) {}
};

struct cipher_type : public UnknownBased<IRsaCipher> {
    using super_type = UnknownBased<IRsaCipher>;

    explicit cipher_type(client_type &c)
            : super_type(IID_ICipher, IID_IRsaCipher)
            , client(c)
    {}

    HRESULT apply_crypto_operation(uint8_t cmd, IInput *in, IOutput *out, IError *err_sink);

    HRESULT STDMETHODCALLTYPE Decrypt(IInput *in, IOutput *out, IError *err_sink);
    HRESULT STDMETHODCALLTYPE Encrypt(IInput *in, IOutput *out, IError *err_sink);

    HRESULT STDMETHODCALLTYPE TrapdoorPub(IInput *in, IOutput *out, IError *err_sink);
    HRESULT STDMETHODCALLTYPE TrapdoorPri(IInput *in, IOutput *out, IError *err_sink);

    client_type &client;
};

template<typename _CharT, typename _Traits>
std::basic_ostream<_CharT, _Traits>&
operator<<(std::basic_ostream<_CharT, _Traits>& __os, client_type::header_type &hdr) {
    __os << "command (" << static_cast<int>(hdr.cmd)
         << "); qualifier (" << static_cast<int>(hdr.qual)
         << "); length (" << static_cast<int>(hdr.len) << ")";
    return __os;
}

template <typename _InIt>
client_type::header_type client_type::send(header_type hdr, _InIt data) {
    data_type buff;
    buff.resize(sizeof(hdr) + hdr.len, 0);
    auto it = std::copy_n(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr), buff.begin());
    if (hdr.len > 0)
        std::copy_n(data, hdr.len, it);

    LOG_DEBUG << "client_type::send: write data to socket " << hdr;
    asio::write(socket, asio::buffer(buff));
    LOG_DEBUG << "client_type::send: done";

    hdr = {};
    LOG_DEBUG << "client_type::send: read response header from socket";
    asio::read(socket, asio::buffer(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr)));
    LOG_DEBUG << "client_type::send: done " << hdr;

    return hdr;
}

template <typename _InIt, typename _OutCont>
client_type::header_type client_type::send(header_type hdr, _InIt data, _OutCont &resp_data) {
    hdr = send(hdr, data);
    if (hdr.len > 0) {
        resp_data.resize(hdr.len, 0);
        LOG_DEBUG << "client_type::send: read response data from socket";
        asio::read(socket, asio::buffer(&resp_data[0], hdr.len));
        LOG_DEBUG << "client_type::send: done";
    }

    return hdr;
}

template <typename _DataT>
client_type::header_type client_type::send_n(header_type hdr, _DataT &&data, size_t size) {
    using namespace std;

    hdr.len = static_cast<uint16_t>(size);
    return send(hdr, reinterpret_cast<
            conditional_t<is_const<remove_reference_t<_DataT>>::value, const uint8_t*, uint8_t*>>(&data));
}

HRESULT cipher_type::apply_crypto_operation(uint8_t cmd, IInput *in, IOutput *out, IError *err_sink) {
    if (in == nullptr || out == nullptr) {
        set_error(err_sink, ErrorCode::IncorrectArgument,
                  "cipher_type::apply_crypto_operation: input and output streams should be specified");
        LOG_ERROR << "cipher_type::apply_crypto_operation: input and output streams should be specified";
        return E_INVALIDARG;
    }

    const DWORD BLOCK_SIZE = 4096;

    LOG_INFO << "cipher_type::apply_crypto_operation: apply operation " << static_cast<int>(cmd);

    try {
        data_type data, resp;
        uint8_t buff[BLOCK_SIZE];
        DWORD sz;
        HRESULT res;
        bool more_data;
        do {
            sz = BLOCK_SIZE;
            if ((res = read_data(in, buff, sz, more_data, err_sink)) != S_OK)
                return res;

            data.insert(data.end(), buff, buff + sz);
        } while (more_data);

        auto hdr = client.send({cmd, 0, static_cast<uint16_t>(data.size())}, data.begin(), resp);
        LOG_DEBUG << "cipher_type::apply_crypto_operation: response size " << resp.size();
        if (hdr.cmd != client_type::SUCCESS) {
            set_error(err_sink, ErrorCode::RemoteError,
                      "cipher_type::apply_crypto_operation: error while data has being been sent to server");
            LOG_ERROR << "cipher_type::apply_crypto_operation: error while data has being been sent to server "
                      << static_cast<int>(hdr.cmd);
            return E_FAIL;
        }

        if ((res = write_data(out, resp.begin(), resp.size(), err_sink)) != S_OK)
            return res;

        LOG_INFO << "cipher_type::apply_crypto_operation: completed";
        return S_OK;

    } catch(std::exception &e) {
        set_error(err_sink, ErrorCode::InternalError, "cipher_type::apply_crypto_operation: operation has been failed");
        LOG_CRITICAL << "cipher_type::apply_crypto_operation: operation has been failed with error: " << e.what();
    } catch(...) {
        set_error(err_sink, ErrorCode::InternalError, "cipher_type::apply_crypto_operation: operation has been failed");
        LOG_CRITICAL << "cipher_type::apply_crypto_operation: operation has been failed with unknown error";
    }

    return E_FAIL;
}

HRESULT cipher_type::Decrypt(IInput *in, IOutput *out, IError *err_sink) {
    LOG_DEBUG << "cipher_type::Decrypt has been called";
    return apply_crypto_operation(client_type::DECRYPT, in, out, err_sink);
}

HRESULT cipher_type::Encrypt(IInput *in, IOutput *out, IError *err_sink) {
    LOG_DEBUG << "cipher_type::Encrypt has been called";
    return apply_crypto_operation(client_type::ENCRYPT, in, out, err_sink);
}

HRESULT cipher_type::TrapdoorPub(IInput *in, IOutput *out, IError *err_sink) {
    LOG_DEBUG << "cipher_type::TrapdoorPub has been called";
    return apply_crypto_operation(client_type::TRAPDOOR_PUB, in, out, err_sink);
}

HRESULT cipher_type::TrapdoorPri(IInput *in, IOutput *out, IError *err_sink) {
    LOG_DEBUG << "cipher_type::TrapdoorPri has been called";
    return apply_crypto_operation(client_type::TRAPDOOR_PRI, in, out, err_sink);
}

cipher_type* create_cipher(ICryptoContext *context, IError *err_sink) {
    auto context_ = dynamic_cast<crypto_context_type*>(context);
    if (context_ == nullptr) {
        set_error(err_sink, ErrorCode::IncorrectArgument,
                  "create_cipher: context should be specified and created by CreateCryptoContext function");
        LOG_ERROR << "create_cipher: context should be specified and created by CreateCryptoContext function";
        return nullptr;
    }

    try {
        if (context_->client.send_n(
                {client_type::CREATE_CIPHER}, client_type::create_cipher_data_type{}).cmd == client_type::SUCCESS)
            return new cipher_type(context_->client);

        set_error(err_sink, ErrorCode::RemoteError, "create_cipher: cipher creating has been failed");

    } catch(std::exception &e) {
        set_error(err_sink, ErrorCode::InternalError, "create_cipher: cipher creating has been failed");
        LOG_CRITICAL << "create_cipher: cipher creating has been failed with error: " << e.what();
    } catch(...) {
        set_error(err_sink, ErrorCode::InternalError, "create_cipher: cipher creating has been failed");
        LOG_CRITICAL << "create_cipher: cipher creating has been failed with unknown error";
    }

    return nullptr;
}

ICipher* __cdecl CreateCipher(ICryptoContext *context, IError *err_sink) {
    LOG_DEBUG << "CreateCipher has been called";
    return create_cipher(context, err_sink);
}

IRsaCipher* __cdecl CreateRsaCipher(ICryptoContext *context, IError *err_sink) {
    LOG_DEBUG << "CreateRsaCipher has been called";
    return create_cipher(context, err_sink);
}

ICryptoContext* __cdecl CreateCryptoContext(uint16_t key_id, const char *ip, uint16_t port, IError *err_sink) {
	LOG_DEBUG << "CreateCryptoContext has been called";
	
	if (ip == nullptr) {
        set_error(err_sink, ErrorCode::IncorrectArgument, "CreateCryptoContext: ip should specified");
        LOG_ERROR << "CreateCryptoContext: ip should specified";
        return nullptr;
    }

    try {
        auto crypto_context = guard(new crypto_context_type);

        crypto_context->client.socket.connect({ip::address::from_string(ip), port});

        LOG_INFO << "CreateCryptoContext: connection with peer " << ip << " port " << port
                  << " has successfully been established";

        if (crypto_context->client.send_n(
                {client_type::CREATE_CRYPTO_CONTEXT},
                client_type::create_crypto_context_data_type{key_id}).cmd == client_type::SUCCESS)
            return crypto_context.release();

        set_error(err_sink, ErrorCode::RemoteError, "CreateCryptoContext: crypto context creating has been failed");

    } catch(std::exception &e) {
        set_error(err_sink, ErrorCode::InternalError, "CreateCryptoContext: crypto context creating has been failed");
        LOG_CRITICAL << "CreateCryptoContext: crypto context creating has been failed with error: " << e.what();
    } catch(...) {
        set_error(err_sink, ErrorCode::InternalError, "CreateCryptoContext: crypto context creating has been failed");
        LOG_CRITICAL << "CreateCryptoContext: crypto context creating has been failed with unknown error";
    }

    return nullptr;
}

}} // namespace griha::hsm