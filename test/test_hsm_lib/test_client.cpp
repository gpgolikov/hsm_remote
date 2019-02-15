//
// Created by griha on 13.01.18.
//
#include <catch.hpp>

#include <crypto/hsm_client/crypto_context.hpp>
#include <crypto/hsm_client/cipher.hpp>
#include <misc/encoding.hpp>
#include <misc/io_manip.hpp>
#include <crypto_win_base.hpp>

#include <griha/tools/guard.hpp>
#include <griha/tools/hexadecimal.hpp>

#include "common.hpp"

using namespace griha::hsm;
using namespace griha::hsm::tools;
using namespace griha::tools;

TEST_CASE("Client - key id 4", "[noHSM]") {
    remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);

    {
        bool res = gen_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);
        INFO("Generate user key in PROV_RSA_FULL enhanced provider" << get_last_error());
        REQUIRE(res);
    }

    Error err_sink;

    auto crypto_context = guard(CreateCryptoContext(4, "127.0.0.1", 8001, &err_sink), unknown_deleter);
    INFO("Create crypto context: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
    REQUIRE(err_sink.code == ErrorCode::Success);
    REQUIRE(crypto_context != nullptr);

    auto cipher = guard(CreateRsaCipher(crypto_context.get(), &err_sink), unknown_deleter);
    INFO("Create crypto context: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
    REQUIRE(err_sink.code == ErrorCode::Success);
    REQUIRE(cipher != nullptr);

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