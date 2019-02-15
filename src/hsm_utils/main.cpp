#include <iostream>
#include <vector>
#include <algorithm>

#include <windows.h>
#include <wincrypt.h>

#include <boost/program_options.hpp>

#include <misc/encoding.hpp>
#include <misc/logger.hpp>
#include <misc/io_manip.hpp>
#include <misc/functional.hpp>

#include <griha/tools/hexadecimal.hpp>
#include <griha/tools/guard.hpp>

namespace po = boost::program_options;

using std::string;
using std::wstring;

using namespace griha::hsm;
using namespace griha::tools;

inline
void usage(std::ostream& os, const po::options_description &descr) {
    os << "Usage: hsm_utils <command> [see command options]" << std::endl << descr << std::endl;
}

void print_help(bool command_list, const po::options_description &descr) {
    if (!command_list) {
        usage(std::cout, descr);
        return;
    }

    std::cout << "Commands:" << std::endl
              << "\texport" << std::endl
              << "\thelp" << std::endl;
}

int main(int argc, char *argv[]) {
    bool pub_key = false, command_list = false;
    DWORD prov_type;
    string prov_name, cont_name, cont_name_trans;

    try {
        // command line options
        po::options_description export_opts("export");
        export_opts.add_options()
                ("public,p", po::bool_switch(&pub_key), "export public key")
                ("prov-name", po::value(&prov_name), "crypto service provider name;")
                ("prov-type", po::value(&prov_type), "crypto service provider type;")
                ("cont-name", po::value(&cont_name), "crypto container name;")
                ("trans-name", po::value(&cont_name_trans)->default_value(""),
                 "crypto container name of transport key;");

        po::options_description help("help");
        help.add_options()
                ("cmd-list", po::bool_switch(&command_list), "show supported command list");

        // Next options allowed at command line, but isn't shown in help
        po::options_description cmd_line;
        cmd_line.add(export_opts).add(help);

        po::variables_map opts;

        if (argc < 2) {
            usage(std::cerr, cmd_line);
            return EXIT_FAILURE;
        }

        if (strcmp(argv[1], "help") == 0) {
            po::store(po::command_line_parser(argc - 1, argv + 1).options(help).run(), opts);
            notify(opts);

            print_help(command_list, cmd_line);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[1], "export") != 0) {
            usage(std::cerr, cmd_line);
            return EXIT_FAILURE;
        }

        po::store(po::command_line_parser(argc - 1, argv + 1).options(export_opts).run(), opts);
        notify(opts);

        HCRYPTPROV h_prov_trans{0};
        BOOL res;
        if (!cont_name_trans.empty() &&
            !CryptAcquireContext(&h_prov_trans,
                                 to_wstr(cont_name_trans).c_str(), to_wstr(prov_name).c_str(), prov_type, 0)) {
            std::cerr << "CryptAcquireContext for \""
                      << cont_name_trans << "\" has returned error " << last_error << std::endl;
            return EXIT_FAILURE;
        }
        auto h_prov_trans_guard = guard(h_prov_trans,
                                        safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0)));

        HCRYPTKEY h_key_trans{0};
        if (h_prov_trans &&
            !CryptGetUserKey(h_prov_trans, AT_KEYEXCHANGE, &h_key_trans) &&
            !CryptGetUserKey(h_prov_trans, AT_SIGNATURE, &h_key_trans)) {
            std::cerr << "CryptGetUserKey for \""
                      << cont_name_trans << "\" has returned error " << last_error << std::endl;
            return EXIT_FAILURE;
        }
        auto h_key_trans_guard = guard(h_key_trans, safed_deleter(CryptDestroyKey));

        HCRYPTPROV h_prov{0};
        if (!CryptAcquireContext(&h_prov, to_wstr(cont_name).c_str(), to_wstr(prov_name).c_str(), prov_type, 0)) {
            std::cerr << "CryptAcquireContext for \""
                      << cont_name << "\" has returned error" << last_error << std::endl;
            return EXIT_FAILURE;
        }
        auto h_prov_guard = guard(h_prov, safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0)));

        HCRYPTKEY h_key{0};
        if (!CryptGetUserKey(h_prov, AT_KEYEXCHANGE, &h_key)) {
            std::cerr << "CryptGetUserKey for \"" << cont_name << "\" has returned error " << last_error << std::endl;
            return EXIT_FAILURE;
        }
        auto h_key_guard = guard(h_key, safed_deleter(CryptDestroyKey));

        std::array<uint8_t, 4096> buffer = {0};
        DWORD sz = buffer.size();
        if (pub_key) { // public key
            buffer.fill(0); // reset buffer to zero
            if (!CryptExportKey(h_key, 0, PUBLICKEYBLOB, 0, buffer.data(), &sz)) {
                std::cerr << "CryptExportKey for public key of \""
                          << cont_name << "\" has returned error " << last_error << std::endl;
                return EXIT_FAILURE;
            }

            std::cout << "Exported public key blob (little-endian): " << std::endl
                      << '\t' << as_hex_n(buffer.begin(), sz) << std::endl << std::endl;

            std::vector<uint8_t> blob;
            blob.assign(buffer.begin(), buffer.end());

            std::cout << "Parsed data (big-endian):" << std::endl;

            uint32_t key_size = *(reinterpret_cast<uint32_t *>(blob.data() + 12)) / 8;
            std::cout << "  Key size:" << std::endl << '\t' << key_size << std::endl;

            size_t o = 12;
            std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // key_size
            o += 4;
            std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // E
            std::cout << "  Exponent:" << std::endl << '\t' << as_hex_n(buffer.begin() + o, 4) << std::endl;
            o += 4;
            std::reverse_copy(blob.data() + o, blob.data() + o + key_size, buffer.data() + o); // module
            std::cout << "  Module:" << std::endl << '\t' << as_hex_n(buffer.begin() + o, key_size) << std::endl;

            return EXIT_SUCCESS;
        }

        // private key

        buffer.fill(0); // reset buffer to zero
        if (!CryptExportKey(h_key, h_key_trans, PRIVATEKEYBLOB, 0, buffer.data(), &sz)) {
            std::cerr << "CryptExportKey for private key of \""
                      << cont_name << "\" has returned error " << last_error << std::endl;
            return EXIT_FAILURE;
        }

        if (h_key_trans) {
            std::cout << "Exported private key blob (encrypted): " << std::endl
                      << '\t' << as_hex_n(buffer.begin(), sz) << std::endl << std::endl;

            sz -= 8;
            if (!CryptDecrypt(h_key_trans, 0, TRUE, 0, buffer.data() + 8, &sz)) {
                std::cerr << "CryptDecrypt for exported private blob of \""
                          << cont_name << "\" has returned error " << last_error << std::endl;
                return EXIT_FAILURE;
            }
            sz += 8;
        }

        std::cout << "Exported private key blob (little-endian): " << std::endl
                  << '\t' << as_hex_n(buffer.begin(), sz) << std::endl << std::endl;

        std::vector<uint8_t> blob;
        blob.assign(buffer.begin(), buffer.end());

        std::cout << "Parsed data (big-endian):" << std::endl;

        uint32_t key_size = *(reinterpret_cast<uint32_t *>(blob.data() + 12)) / 8;
        std::cout << "  Key size:" << std::endl << '\t' << key_size << std::endl;

        size_t o = 12;
        std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // key_size
        o += 4;
        std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // E
        std::cout << "  Exponent:" << std::endl << '\t' << as_hex_n(buffer.begin() + o, 4) << std::endl;
        o += 4;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size, buffer.data() + o); // module
        std::cout << "  Module:" << std::endl << '\t' << as_hex_n(buffer.begin() + o, key_size) << std::endl;
        o += key_size;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // P
        std::cout << "  P:" << std::endl << '\t' << as_hex_n(buffer.begin() + o, key_size / 2) << std::endl;
        o += key_size / 2;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // Q
        std::cout << "  Q:" << std::endl << '\t' << as_hex_n(buffer.begin() + o, key_size / 2) << std::endl;
        o += key_size / 2;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // DP
        std::cout << "  DP:" << std::endl << '\t' << as_hex_n(buffer.begin() + o, key_size / 2) << std::endl;
        o += key_size / 2;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // DQ
        std::cout << "  DQ:" << std::endl << '\t' << as_hex_n(buffer.begin() + o, key_size / 2) << std::endl;
        o += key_size / 2;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // InverseQ
        std::cout << "  InverseQ:" << std::endl << '\t' << as_hex_n(buffer.begin() + o, key_size / 2) << std::endl;
        o += key_size / 2;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size, buffer.data() + o); // D
        std::cout << "  D:" << std::endl << '\t' << as_hex_n(buffer.begin() + o, key_size) << std::endl;

    } catch (std::exception &e) {
        LOG_CRITICAL << "error in main(): " << e.what();
    }

    return EXIT_FAILURE;
}