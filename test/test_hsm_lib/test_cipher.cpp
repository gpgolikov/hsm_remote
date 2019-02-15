//
// Created by griha on 17.12.17.
//
#include <catch.hpp>

#include <array>

#include <crypto/hsm_lib/crypto_context.hpp>
#include <crypto/hsm_lib/cipher.hpp>
#include <crypto/crypto_types.hpp>
#include <misc/encoding.hpp>
#include <misc/io_manip.hpp>

#include <crypto_context_impl.hpp>
#include <crypto_win_base.hpp>

#include <griha/tools/guard.hpp>
#include <griha/tools/hexadecimal.hpp>

#include "common.hpp"

using namespace std;
using namespace griha::hsm;
using namespace griha::hsm::tools;
using namespace griha::tools;

TEST_CASE("Creation cipher", "[Cipher][noHSM]") {

    SECTION("key generate - RSA default") {
        remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);

        bool r = gen_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);
        INFO("Generate user key in PROV_RSA_FULL enhanced provider" << get_last_error());
        REQUIRE(r);

        Error err_sink;

        auto crypto_context = guard(
                dynamic_cast<CryptoContext*>(CreateCryptoContext(MS_ENHANCED_PROV, PROV_RSA_FULL,
                                                                 CONT_NAME, nullptr, nullptr, nullptr, &err_sink)),
                unknown_deleter);

        INFO("Create crypto context: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
        REQUIRE(err_sink.code == ErrorCode::Success);
        REQUIRE(crypto_context != nullptr);

        auto cipher = guard(CreateRsaCipher(crypto_context.get(), &err_sink), unknown_deleter);
        INFO("Create cipher: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
        REQUIRE(err_sink.code == ErrorCode::Success);
        REQUIRE(cipher != nullptr);

        SECTION("decrypt/encrypt - 16 bytes") {
            Input input;
            input.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

            Output output;

            // Encrypt plain text

            HRESULT res = cipher->Encrypt(&input, &output, &err_sink);

            INFO("Encrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: ciphered data " << output.data.size() << " bytes; "
                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Decrypt encrypted data

            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->Decrypt(&input, &output, &err_sink);

            INFO("Decrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Decrypt: plain text " << as_hex(output.data.begin(), output.data.end()).c_str());
        }

        SECTION("decrypt/encrypt on private/public key - 16 bytes") {
            Input input;
            input.data = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // PKCS1 v 1.5 header
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0,};

            Output output;

            // Encrypt data on private key

            HRESULT res = cipher->Decrypt(&input, &output, &err_sink);

            INFO("Decrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE_FALSE(err_sink.code == ErrorCode::Success);
            REQUIRE_FALSE(res == S_OK);

            WARN("Decrypt: plain text " << as_hex(output.data.begin(), output.data.end()).c_str());

//            //Encrypt plain text
//
//            input.data = output.data;
//            input.offset = 0;
//            output.data.clear();
//
//            bool res = cipher->Encrypt(&input, &output, &err_sink);
//
//            INFO("Encrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
//            REQUIRE(err_sink.code == ErrorCode::Success);
//            REQUIRE(res);
//
//            WARN("Encrypt: ciphered data " << output.data.size() << " bytes; "
//                                           << as_hex(output.data.begin(), output.data.end()).c_str());

        }

        SECTION("decrypt/encrypt - 117 bytes (RSA module size is 128 bytes)") {
            Input input;
            input.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4,};

            Output output;

            // Encrypt plain text

            HRESULT res = cipher->Encrypt(&input, &output, &err_sink);

            INFO("Encrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: ciphered data " << output.data.size() << " bytes; "
                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Decrypt encrypted data

            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->Decrypt(&input, &output, &err_sink);

            INFO("Decrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: plain text " << as_hex(output.data.begin(), output.data.end()).c_str());
        }

        SECTION("decrypt/encrypt - 128 bytes (RSA module size is 128 bytes)") {
            Input input;
            input.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,};

            Output output;

            // Encrypt plain text

            HRESULT res = cipher->Encrypt(&input, &output, &err_sink);

            INFO("Encrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: ciphered data " << output.data.size() << " bytes "
                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Decrypt encrypted data

            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->Decrypt(&input, &output, &err_sink);

            INFO("Decrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: plain text " << output.data.size() << " bytes "
                                        << as_hex(output.data.begin(), output.data.end()).c_str());
        }

        SECTION("decrypt/encrypt - 126 bytes (RSA module size is 128 bytes)") {
            Input input;
            input.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,};

            Output output;

            // Encrypt plain text

            HRESULT res = cipher->Encrypt(&input, &output, &err_sink);

            INFO("Encrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: ciphered data " << output.data.size() << " bytes "
                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Decrypt encrypted data

            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->Decrypt(&input, &output, &err_sink);

            INFO("Decrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: plain text " << output.data.size() << " bytes "
                                        << as_hex(output.data.begin(), output.data.end()).c_str());
        }

        SECTION("trapdoor permutation - 16 bytes (RSA module size is 128 bytes)") {
            Input input;
            input.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,};

            Output output;

            // Apply RSA on plain text

            HRESULT res = cipher->TrapdoorPub(&input, &output, &err_sink);

            INFO("TrapdoorPub: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("TrapdoorPub: after direct permutation " << output.data.size() << " bytes "
                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Apply inverse RSA

            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->TrapdoorPri(&input, &output, &err_sink);

            INFO("TrapdoorPri: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("TrapdoorPri: after reverse permutation " << output.data.size() << " bytes "
                                        << as_hex(output.data.begin(), output.data.end()).c_str());
        }

        SECTION("trapdoor permutation (PKCS1 v1.5 simulation) - 16 bytes (RSA module size is 128 bytes)") {
            Input input;
            input.data = { 0, 2, // PKCS1 mode 2
                           // Random sequence
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4,
                           0, // padding
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,};

            Output output;

            // Apply RSA on plain text - PKCS1 encryption mode 2

            HRESULT res = cipher->TrapdoorPub(&input, &output, &err_sink);

            INFO("TrapdoorPub: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("TrapdoorPub: after direct permutation " << output.data.size() << " bytes "
                                                          << as_hex(output.data.begin(), output.data.end()).c_str());

            // Decrypt encrypted data (Crypto API expects encrypted data in little-endian format)

            input.data.resize(output.data.size(), 0);
            std::copy(output.data.rbegin(), output.data.rend(), input.data.begin());
//            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->Decrypt(&input, &output, &err_sink);

            INFO("Decrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Decrypt: plain text " << output.data.size() << " bytes "
                                        << as_hex(output.data.begin(), output.data.end()).c_str());
        }

        SECTION("trapdoor permutation (PKCS1 v1.5 extraction) - 16 bytes (RSA module size is 128 bytes)") {
            Input input;
            input.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, };

            Output output;

            // Encrypt plain text

            HRESULT res = cipher->Encrypt(&input, &output, &err_sink);

            INFO("Encrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: ciphered data " << output.data.size() << " bytes; "
                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Apply inverse RSA (Crypto API expects encrypted data in little-endian format)

            input.data.resize(output.data.size(), 0);
            std::copy(output.data.rbegin(), output.data.rend(), input.data.begin());
//            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->TrapdoorPri(&input, &output, &err_sink);

            INFO("TrapdoorPri: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("TrapdoorPri: after reverse permutation " << output.data.size() << " bytes "
                                                           << as_hex(output.data.begin(), output.data.end()).c_str());
        }

        crypto_context.reset();
        r = remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);
        INFO("Remove user key in PROV_RSA_FULL enhanced provider" << get_last_error());
        REQUIRE(r);
    }

    SECTION("key generate - DES session key") {
        remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);

        array<byte, 20> blob_des = {
                0x08, 0x02, 0x00, 0x00, 0x01, 0x66, 0x00, 0x00, // BLOB header
                0x08, 0x00, 0x00, 0x00,                     // key length, in bytes
                0xf1, 0x0e, 0x25, 0x7c, 0x6b, 0xce, 0x0d, 0x34  // DES key with parity
        };

        HCRYPTPROV h_prov{0};
        REQUIRE(CryptAcquireContext(&h_prov, CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET));
        INFO("Create container error: " << get_last_error());

        auto h_prov_guard = guard(h_prov, safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0)));

        HCRYPTKEY h_key{0};
        REQUIRE(CryptImportKey(h_prov, &blob_des[0], blob_des.size(), 0, CRYPT_EXPORTABLE, &h_key));
        INFO("Import DES session key error: " << get_last_error());

        auto h_key_guard = guard(h_key, safed_deleter(CryptDestroyKey));

        Error err_sink;

        CryptoContext crypto_context;
        crypto_context.h_prov = PtrToUlong(h_prov_guard.release());
        crypto_context.h_key_exchange = PtrToUlong(h_key_guard.release());

        auto cipher = guard(CreateCipher(&crypto_context, CipherMode::ECB, Padding::Pkcs5, &err_sink),
                            unknown_deleter);
        INFO("Create cipher: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
        REQUIRE(err_sink.code == ErrorCode::Success);
        REQUIRE(cipher != nullptr);

        SECTION("decrypt/encrypt - 16 bytes") {
            Input input;
            input.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

            Output output;

            // Encrypt plain text

            HRESULT res = cipher->Encrypt(&input, &output, &err_sink);

            INFO("Encrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: ciphered data " << output.data.size() << " bytes; "
                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Decrypt encrypted data

            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->Decrypt(&input, &output, &err_sink);

            INFO("Decrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Decrypt: plain text " << output.data.size() << " bytes; "
                                        << as_hex(output.data.begin(), output.data.end()).c_str());
        }

        SECTION("decrypt/encrypt - 4096 bytes") {
            Input input;
            input.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,};

            Output output;

            // Encrypt plain text

            HRESULT res = cipher->Encrypt(&input, &output, &err_sink);

            INFO("Encrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: ciphered data " << output.data.size() << " bytes; "
                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Decrypt encrypted data

            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->Decrypt(&input, &output, &err_sink);

            INFO("Decrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Decrypt: plain text " << output.data.size() << " bytes; "
                                        << as_hex(output.data.begin(), output.data.end()).c_str());
        }
    }
}

TEST_CASE("HSM cipher - test_griha0001 RSA", "[Cipher][HSM]") {

    SECTION("key test_griha0001 with transport key test_griha_trans0001 - no password") {

        Error err_sink;
        auto crypto_context = guard(
                CreateCryptoContext(PROVNAME_CRYPTOPRO_HSM_RSA, PROV_CRYPTOPRO_HSM_RSA,
                                    CONT_NAME, nullptr, CONT_NAME_TRANS, nullptr, &err_sink),
                unknown_deleter);

        {
            INFO("Create by provider type: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(crypto_context != nullptr);
        }

        auto cipher = guard(CreateRsaCipher(crypto_context.get(), &err_sink), unknown_deleter);
        INFO("Create cipher: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
        REQUIRE(err_sink.code == ErrorCode::Success);
        REQUIRE(cipher != nullptr);

        SECTION("trapdoor permutation - 16 bytes (RSA module size is 128 bytes)") {
            Input input;
            input.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,};

            Output output;

            // Apply RSA on plain text

            HRESULT res = cipher->TrapdoorPub(&input, &output, &err_sink);

            INFO("TrapdoorPub: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("TrapdoorPub: after direct permutation " << output.data.size() << " bytes "
                                                          << as_hex(output.data.begin(), output.data.end()).c_str());

            // Apply inverse RSA

            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->TrapdoorPri(&input, &output, &err_sink);

            INFO("TrapdoorPri: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("TrapdoorPri: after reverse permutation " << output.data.size() << " bytes "
                                                           << as_hex(output.data.begin(), output.data.end()).c_str());
        }

        SECTION("trapdoor permutation (PKCS1 v1.5 simulation) - 16 bytes (RSA module size is 128 bytes)") {
            Input input;
            input.data = { 0, 2, // PKCS1 mode 2
                    // Random sequence
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           1, 2, 3, 4,
                           0, // padding
                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,};

            Output output;

            // Apply RSA on plain text - PKCS1 encryption mode 2

            HRESULT res = cipher->TrapdoorPub(&input, &output, &err_sink);

            INFO("TrapdoorPub: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("TrapdoorPub: after direct permutation " << output.data.size() << " bytes "
                                                          << as_hex(output.data.begin(), output.data.end()).c_str());

            // Decrypt encrypted data (Crypto API expects encrypted data in little-endian format)

            input.data.resize(output.data.size(), 0);
            std::copy(output.data.rbegin(), output.data.rend(), input.data.begin());
//            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->Decrypt(&input, &output, &err_sink);

            INFO("Decrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Decrypt: plain text " << output.data.size() << " bytes "
                                        << as_hex(output.data.begin(), output.data.end()).c_str());
        }

        SECTION("trapdoor permutation (PKCS1 v1.5 extraction) - 16 bytes (RSA module size is 128 bytes)") {
            Input input;
            input.data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, };

            Output output;

            // Encrypt plain text

            HRESULT res = cipher->Encrypt(&input, &output, &err_sink);

            INFO("Encrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: ciphered data " << output.data.size() << " bytes; "
                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Apply inverse RSA (Crypto API expects encrypted data in little-endian format)

            input.data.resize(output.data.size(), 0);
            std::copy(output.data.rbegin(), output.data.rend(), input.data.begin());
//            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->TrapdoorPri(&input, &output, &err_sink);

            INFO("TrapdoorPri: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("TrapdoorPri: after reverse permutation " << output.data.size() << " bytes "
                                                           << as_hex(output.data.begin(), output.data.end()).c_str());
        }
    }
}

TEST_CASE("HSM cipher - test_griha0001 3DES", "[Cipher][HSM-3DES]") {

    SECTION("key test_griha0001 - no password") {

        Error err_sink;
        auto crypto_context = guard(
                CreateCryptoContext(PROVNAME_CRYPTOPRO_HSM_RSA, PROV_CRYPTOPRO_HSM_RSA, CONT_NAME, nullptr,
                                    nullptr, nullptr, &err_sink),
                unknown_deleter);

        {
            INFO("Create by provider type: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(crypto_context != nullptr);
        }

        auto cipher = guard(CreateCipher(crypto_context.get(), CipherMode::ECB, Padding::Pkcs5, &err_sink),
                            unknown_deleter);
        INFO("Create cipher: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
        REQUIRE(err_sink.code == ErrorCode::Success);
        REQUIRE(cipher != nullptr);

        SECTION("decrypt/encrypt - 16 bytes") {
            Input input;
            input.data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

            Output output;

            // Encrypt plain text

            HRESULT res = cipher->Encrypt(&input, &output, &err_sink);

            INFO("Encrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Encrypt: ciphered data " << output.data.size() << " bytes; "
                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Decrypt encrypted data

            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->Decrypt(&input, &output, &err_sink);

            INFO("Decrypt: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("Decrypt: plain text " << output.data.size() << " bytes; "
                                        << as_hex(output.data.begin(), output.data.end()).c_str());
        }
    }
}

TEST_CASE("HSM cipher - test_griha0001 RSA real data", "[Cipher][HSM][RealData]") {

    SECTION("key test_griha0001 with transport key test_griha_trans0001 - no password") {

        Error err_sink;
        auto crypto_context = guard(
                CreateCryptoContext(PROVNAME_CRYPTOPRO_HSM_RSA, PROV_CRYPTOPRO_HSM_RSA,
                                    CONT_NAME, nullptr, CONT_NAME_TRANS, nullptr, &err_sink),
                unknown_deleter);

        {
            INFO("Create by provider type: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(crypto_context != nullptr);
        }

        auto cipher = guard(CreateRsaCipher(crypto_context.get(), &err_sink), unknown_deleter);
        INFO("Create cipher: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
        REQUIRE(err_sink.code == ErrorCode::Success);
        REQUIRE(cipher != nullptr);

        SECTION("trapdoor permutation - 120 bytes (RSA module size is 128 bytes)") {
            Input input;
            std::vector<uint8_t> data = {
                    0xFC, 0xC7, 0xF7, 0x03, 0xAC, 0x5F, 0xA3, 0x84, 0x3C, 0x90, 0x77, 0xAF, 0x8A, 0xCE, 0xF9, 0xE4,
                    0x32, 0x36, 0x7B, 0xED, 0xD2, 0x84, 0xA8, 0xF0, 0x3B, 0xAB, 0x76, 0xCA, 0x86, 0x00, 0xCB, 0xFD,
                    0x81, 0x55, 0x4D, 0x51, 0xEB, 0xA1, 0x62, 0xA2, 0x9F, 0xD0, 0x34, 0xA9, 0xE8, 0xEA, 0x54, 0x76,
                    0xBD, 0xE8, 0x6F, 0x56, 0xE6, 0x0C, 0x53, 0x77, 0x1F, 0x06, 0xC8, 0x01, 0xE9, 0xD8, 0xFE, 0x3C,
                    0xC4, 0x79, 0x2E, 0x34, 0x80, 0xA7, 0xF9, 0x91, 0xD3, 0xD8, 0x4E, 0x01, 0x50, 0xFF, 0x08, 0x50,
                    0x56, 0x00, 0x0D, 0x9E, 0x90, 0x75, 0x17, 0x74, 0x02, 0xD6, 0x32, 0xE4, 0xD9, 0x61, 0xB9, 0xC7,
                    0xD2, 0xF8, 0xE5, 0x6F, 0xBC, 0x20, 0xF5, 0x16, 0xEF, 0xDE, 0x83, 0x0D, 0xBE, 0x51, 0x27, 0x20,
                    0xFE, 0x78, 0xAA, 0xE9, 0xCB, 0x5F, 0xAB, 0x4F};


//            std::copy(data.rbegin(), data.rend(), std::back_inserter(input.data));
            input.data.assign(data.begin(), data.end());

            Output output;

            // Apply RSA on plain text

            HRESULT res = cipher->TrapdoorPri(&input, &output, &err_sink);

            INFO("TrapdoorPri: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("TrapdoorPri: after reverse permutation " << output.data.size() << " bytes "
                                                           << as_hex(output.data.begin(), output.data.end()).c_str());

            // Apply inverse RSA

            input.data = output.data;
            input.offset = 0;
            output.data.clear();

            res = cipher->TrapdoorPub(&input, &output, &err_sink);

            INFO("TrapdoorPub: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(res == S_OK);

            WARN("TrapdoorPub: after direct permutation " << output.data.size() << " bytes "
                                                          << as_hex(output.data.begin(), output.data.end()).c_str());
        }
    }
}