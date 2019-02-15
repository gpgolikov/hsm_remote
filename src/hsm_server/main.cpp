#include <iostream>
#include <vector>
#include <algorithm>

#include <boost/property_tree/xml_parser.hpp>
#include <boost/program_options.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <crypto/hsm_lib/crypto_context.hpp>
#include <crypto/hsm_lib/cipher.hpp>
#include <misc/encoding.hpp>
#include <misc/logger.hpp>
#include <misc/filesystem.hpp>

#include <griha/tools/hexadecimal.hpp>

#include "error_sink.hpp"
#include "io_crypto.hpp"

namespace po = boost::program_options;
namespace pt = boost::property_tree;
namespace asio = boost::asio;

using std::string;
using std::wstring;
using asio::ip::tcp;
using boost::system::error_code;

using namespace griha::hsm;
using namespace griha::tools;

inline
void usage(std::ostream& os, const po::options_description &descr) {
    os << "Usage: hsm_server [options] <port>" << std::endl << descr << std::endl;
}

class session : public std::enable_shared_from_this<session> {

    enum { TIMEOUT_CMD = 300, TIMEOUT = 30 }; // seconds
    enum { PING = 1, CREATE_CRYPTO_CONTEXT, CREATE_CIPHER, DECRYPT, ENCRYPT, TRAPDOOR_PUB, TRAPDOOR_PRI };
    enum { SUCCESS = 0, ERR_INCORRECT_COMMAND, ERR_BAD_DATA, ERR_NOT_INITIALIZED, ERR_BAD_KEY_ID, ERR_INTERNAL,
        ERR_CRYPTO_CONTEXT_ALREADY_CREATED, ERR_CIPHER, ERR_UNKNOWN };

    template<typename _CharT, typename _Traits>
    friend std::basic_ostream<_CharT, _Traits>&
    operator<<(std::basic_ostream<_CharT, _Traits>& __os, class session &s);

    typedef std::vector<uint8_t> data_type;

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

public:
    explicit session(tcp::socket socket, const pt::ptree &pkeys)
            : socket_(std::move(socket))
            , pkeys_(pkeys)
            , timer_(socket_.get_io_service())
            , strand_(socket_.get_io_service()) {
        LOG_INFO << "New session has been established; peer " << socket_.remote_endpoint();
    }

    void run() {
        auto self(shared_from_this());
        // command handler
        asio::spawn(strand_,
                    [this, self](asio::yield_context yield) {
                        using asio::buffer;

                        try {
                            header_type hdr;
                            while (true) {
								hdr = {};

                                // wait new command
                                LOG_DEBUG << *this << "; command handler: wait new command";
                                timer_.expires_from_now(std::chrono::seconds(TIMEOUT_CMD));
                                asio::async_read(socket_,
                                                 buffer(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr)),
                                                 yield);

                                LOG_DEBUG << *this << "; command handler: command received - "
                                        "command (" << static_cast<int>(hdr.cmd) << "); "
                                        "qualifier (" << static_cast<int>(hdr.qual) << "); "
                                        "data length (" << hdr.len << ")";

                                data_type resp;
                                if (hdr.cmd == PING) {
                                    LOG_DEBUG << *this << "; PING command has been requested";
                                    hdr = { SUCCESS };
                                } else {
                                    data_type data;
                                    // read data
                                    if (hdr.len) {
                                        data.resize(hdr.len, 0);
                                        timer_.expires_from_now(std::chrono::seconds(TIMEOUT));
                                        asio::async_read(socket_, buffer(data), yield);
                                    }

                                    hdr = { process_command(hdr.cmd, hdr.qual, data, resp) };
                                }

                                hdr.len = static_cast<uint16_t>(resp.size());
                                resp.insert(resp.begin(),
                                            reinterpret_cast<uint8_t*>(&hdr),
                                            reinterpret_cast<uint8_t*>(&hdr) + sizeof(hdr));

                                timer_.expires_from_now(std::chrono::seconds(TIMEOUT));
                                asio::async_write(socket_, buffer(resp), yield);

                                LOG_DEBUG << *this << "; command handler: command has been completed";
                            }
                        }
                        catch (std::exception &e) {
                            LOG_ERROR << *this << "; command handler: " << e.what();
                            socket_.close();
                            timer_.cancel();
                        }
                    });

        // timeout handler
        asio::spawn(strand_,
                    [this, self](asio::yield_context yield) {
                        while (socket_.is_open()) {
                            error_code ec;
                            timer_.async_wait(yield[ec]); // suppress exceptions
                            if (timer_.expires_from_now() <= std::chrono::seconds(0)) {
                                socket_.close();
                                LOG_ERROR << "session " << *this << " has been timed out";
                            }
                        }
                    });

        LOG_INFO << *this << " has been ran";
    }

private:
    uint8_t process_command(uint8_t cmd, uint8_t qual, const data_type &data, data_type &resp) noexcept {
        using namespace griha::hsm;

        try {
            switch (cmd) {
                case CREATE_CRYPTO_CONTEXT:
                    if (data.size() != sizeof(create_crypto_context_data_type)) {
                        LOG_ERROR << *this << "; CREATE_CRYPTO_CONTEXT: incorrect data length";
                        return ERR_BAD_DATA;
                    }

                    return process_command(reinterpret_cast<const create_crypto_context_data_type *>(data.data()),
                                           resp);

                case CREATE_CIPHER:
                    if (data.size() != sizeof(create_cipher_data_type)) {
                        LOG_ERROR << *this << "; CREATE_CIPHER: incorrect data length";
                        return ERR_BAD_DATA;
                    }

                    // create fake data - for future use
                    return process_command(reinterpret_cast<const create_cipher_data_type *>(data.data()),
                                           resp);

                case DECRYPT:
                case ENCRYPT:
                case TRAPDOOR_PUB:
                case TRAPDOOR_PRI:
                    break;

                default:
                    return ERR_INCORRECT_COMMAND;
            }

            if (!cipher_) {
                LOG_ERROR << *this << "; process_command: not initialized for ciphering commands";
                return ERR_NOT_INITIALIZED;
            }

            error_sink_type err_sink;
            input_type input;
            output_type output;
            input.data.assign(data.begin(), data.end());

            HRESULT res;
            switch (cmd) {
                case DECRYPT:
                    res = cipher_->Decrypt(&input, &output, &err_sink);
                    break;

                case ENCRYPT:
                    res = cipher_->Encrypt(&input, &output, &err_sink);
                    break;

                case TRAPDOOR_PUB:
                    res = dynamic_cast<IRsaCipher&>(*cipher_).TrapdoorPub(&input, &output, &err_sink);
                    break;

                case TRAPDOOR_PRI:
                    res = dynamic_cast<IRsaCipher&>(*cipher_).TrapdoorPri(&input, &output, &err_sink);
                    break;
            }

            if (res != S_OK) {
                LOG_ERROR_W << *this << "; process_command: cipher error - " << err_sink.message
                            << " (returned " << std::hex << std::showbase << res << ")";
                return ERR_CIPHER;
            }

            resp.assign(output.data.begin(), output.data.end());
            return SUCCESS;
        }
        catch (std::exception &e) {
            LOG_CRITICAL << *this << "; process_command: " << e.what();
        }
        catch (...) {
            LOG_CRITICAL << *this << "; process_command: unknown error";
        }

        return ERR_UNKNOWN;
    }

    uint8_t process_command(const create_crypto_context_data_type *data, data_type &resp) {
        LOG_DEBUG << *this << "; CREATE_CRYPTO_CONTEXT command has been requested - "
                "key identifier (" << data->key_id << ")";

        if (crypto_context_) {
            LOG_ERROR << *this << "; CREATE_CRYPTO_CONTEXT: crypto context has already been created";
            return ERR_CRYPTO_CONTEXT_ALREADY_CREATED;
        }

        auto it = std::find_if(pkeys_.begin(), pkeys_.end(), [data](pt::ptree::value_type &pkey) -> bool {
            return pkey.second.get<uint16_t>("<xmlattr>.id") == data->key_id;
        });
        if (it == pkeys_.end()) {
            LOG_ERROR << *this << "; CREATE_CRYPTO_CONTEXT: unknown key identifier " << data->key_id;
            return ERR_BAD_KEY_ID;
        }

        pkey_ = it->second;

        auto prov_type = pkey_.get<DWORD>("provider.<xmlattr>.type");
        string prov_name = pkey_.get<string>("provider.<xmlattr>.name", ""),
                cont_name = pkey_.get<string>("container.<xmlattr>.name"),
                cont_pass = pkey_.get<string>("container.<xmlattr>.password", "");

        LOG_DEBUG << *this << "; CREATE_CRYPTO_CONTEXT: "
                "provider name (" << prov_name << "); "
                          "provider type (" << prov_type << "); "
                          "container name (" << cont_name << ")";

        error_sink_type err_sink;

        auto trans_key = pkey_.get_child_optional("trans_key");
        if (!trans_key)
            crypto_context_.reset(
                    CreateCryptoContext(prov_name.empty() ? nullptr : to_wstr(prov_name).c_str(), prov_type,
                                        to_wstr(cont_name).c_str(), cont_pass.empty() ? nullptr : cont_pass.c_str(),
                                        nullptr, nullptr,
                                        &err_sink));
        else {
            string tkey_name = pkey_.get<string>("trans_key.<xmlattr>.cont_name"),
                    tkey_pass = pkey_.get<string>("trans_key.<xmlattr>.password", "");
            LOG_DEBUG << *this << "; CREATE_CRYPTO_CONTEXT: "
                    "transport key container name (" << tkey_name << "); ";

            crypto_context_.reset(
                    CreateCryptoContext(prov_name.empty() ? nullptr : to_wstr(prov_name).c_str(), prov_type,
                                        to_wstr(cont_name).c_str(), cont_pass.empty() ? nullptr : cont_pass.c_str(),
                                        to_wstr(tkey_name).c_str(), tkey_pass.empty() ? nullptr : tkey_pass.c_str(),
                                        &err_sink));
        }

        if (!crypto_context_) {
            LOG_ERROR_W << *this << "; CREATE_CRYPTO_CONTEXT: error while crypto context has being been created - "
                               << err_sink.message;
            return ERR_INTERNAL;
        }

        LOG_INFO << *this << "; CREATE_CRYPTO_CONTEXT: crypto context has been created";

        return SUCCESS;
    }

    uint8_t process_command(const create_cipher_data_type *data, data_type &resp) {
        LOG_DEBUG << *this << "; CREATE_CIPHER command has been requested";

        if (cipher_) {
            LOG_ERROR << *this << "; CREATE_CIPHER: cipher has already been created";
            return ERR_CRYPTO_CONTEXT_ALREADY_CREATED;
        }

        if (!crypto_context_) {
            LOG_ERROR << *this << "; CREATE_CIPHER: not initialized";
            return ERR_NOT_INITIALIZED;
        }

        auto symm = pkey_.get_child_optional("symmetric");

        error_sink_type err_sink;
        if (!symm)
            cipher_.reset(CreateRsaCipher(crypto_context_.get(), &err_sink));
        else
            cipher_.reset(CreateCipher(crypto_context_.get(),
                                       symm.value().get<CipherMode>("<xmlattr>.mode", CipherMode::ECB),
                                       symm.value().get<Padding>("<xmlattr>.padding", Padding::Zero),
                                       &err_sink));

        if (!cipher_) {
            LOG_ERROR_W << *this << "; CREATE_CIPHER: error while cipher has being been created - "
                        << err_sink.message;
            return ERR_INTERNAL;
        }

        LOG_INFO << *this << "; CREATE_CIPHER: cipher has been created";

        return SUCCESS;
    }

private:
    tcp::socket socket_;
    pt::ptree pkeys_;
    asio::steady_timer timer_;
    asio::io_service::strand strand_;

    std::unique_ptr<ICryptoContext, unknown_deleter_type> crypto_context_;
    std::unique_ptr<ICipher, unknown_deleter_type> cipher_;
    pt::ptree pkey_;
};

template<typename _CharT, typename _Traits>
std::basic_ostream<_CharT, _Traits>&
operator<<(std::basic_ostream<_CharT, _Traits>& __os, session &s) {
    __os << "session " << s.socket_.remote_endpoint();
	return __os;
}

int main(int argc, char *argv[]) {
    bool opt_help;
    string conf_file;
    unsigned short port;

    try {
        // command line options
        po::options_description generic("Options");
        generic.add_options()
                ("help,h", po::bool_switch(&opt_help), "prints out this message;")
                ("conf-file", po::value(&conf_file)->default_value(
                        from_wstr(get_executable_path() + L"\\hsm_server.conf")),
                 "path to the file that contains configuration;");

        // Next options allowed at command line, but isn't shown in help
        po::options_description hidden("Hidden options");
        hidden.add_options()
                ("port", po::value(&port)->default_value(8001), "listening port;");

        po::positional_options_description pos;
        pos.add("port", 1);

        po::options_description cmd_line, visible;
        cmd_line.add(generic).add(hidden);
        visible.add(generic);

        po::variables_map opts;
        po::store(po::command_line_parser(argc, argv).options(cmd_line).positional(pos).run(), opts);

        notify(opts);

        if (opt_help) {
            usage(std::cout, visible);
            return EXIT_SUCCESS;
        }

        pt::ptree props;
        pt::read_xml(conf_file, props, pt::xml_parser::no_comments);
        pt::ptree pkeys = props.get_child("hsm.keys");

        asio::io_service service;
        asio::spawn(service,
                    [&service, &pkeys, port](asio::yield_context yield) {
                        tcp::acceptor acceptor(service, tcp::endpoint(tcp::v4(), port));

                        while (true) {
                            tcp::socket socket(service);
                            error_code ec;
                            acceptor.async_accept(socket, yield[ec]);
                            if (!ec) std::make_shared<session>(std::move(socket), pkeys)->run();
                        }
                    });

        LOG_INFO << "Server started";
        service.run();
        LOG_INFO << "Server stopped";

        return EXIT_SUCCESS;

    } catch (std::exception &e) {
        LOG_CRITICAL << "error in main(): " << e.what();
    }

    return EXIT_FAILURE;
}