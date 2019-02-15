//
// Created by griha on 15.12.17.
//
#include <catch.hpp>

//#include <array>

#include <crypto/hsm_lib/crypto_context.hpp>
#include <crypto/crypto_types.hpp>
#include <misc/encoding.hpp>
#include <misc/io_manip.hpp>

#include <griha/tools/guard.hpp>

#include <crypto_win_base.hpp>

#include "common.hpp"

//using namespace std;
using namespace griha::hsm;
using namespace griha::hsm::tools;
using namespace griha::tools;

TEST_CASE("Creation crypto context", "[CryptoContext][noHSM]") {

    SECTION("key generate") {
        remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);

        {
            bool res = gen_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);
            INFO("Generate user key in PROV_RSA_FULL enhanced provider" << get_last_error());
            REQUIRE(res);
        }

        Error err_sink;

        //create by provider type
        auto crypto_context = guard(
                CreateCryptoContext(nullptr, PROV_RSA_FULL, CONT_NAME, nullptr, nullptr, nullptr, &err_sink), unknown_deleter);

        {
            INFO("Create by provider type: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(crypto_context != nullptr);
        }

        //create by full provider information
        crypto_context.reset();
        crypto_context.reset(
                CreateCryptoContext(MS_ENHANCED_PROV, PROV_RSA_FULL, CONT_NAME, nullptr, nullptr, nullptr, &err_sink));

        {
            INFO("Create by provider type: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(crypto_context != nullptr);
        }

        crypto_context.reset();
        {
            bool res = remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);
            INFO("Remove user key in PROV_RSA_FULL enhanced provider" << get_last_error());
            REQUIRE(res);
        }
    }

//    SECTION("key import") {
//        remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);
//
//        {
//            array<byte, 20> blob_des = {
//                    0x08,0x02,0x00,0x00,0x01,0x66,0x00,0x00, // BLOB header
//                    0x08,0x00,0x00,0x00,                     // key length, in bytes
//                    0xf1,0x0e,0x25,0x7c,0x6b,0xce,0x0d,0x34  // DES key with parity
//            };
//            bool res = import_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);
//            INFO("Generate DES key in PROV_RSA_FULL enhanced provider" << get_last_error());
//            REQUIRE(res);
//        }
//
//        Error err_sink;
//
//        //create by provider type
//        auto crypto_context = guard(
//                CreateCryptoContext(nullptr, PROV_RSA_FULL, CONT_NAME, nullptr, &err_sink), unknown_deleter);
//
//        {
//            INFO("Create by provider type: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
//            REQUIRE(err_sink.code == ErrorCode::Success);
//            REQUIRE(crypto_context != nullptr);
//        }
//
//        //create by full provider information
//        crypto_context.reset();
//        crypto_context.reset(
//                CreateCryptoContext(MS_ENHANCED_PROV, PROV_RSA_FULL, CONT_NAME, nullptr, &err_sink));
//
//        {
//            INFO("Create by provider type: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
//            REQUIRE(err_sink.code == ErrorCode::Success);
//            REQUIRE(crypto_context != nullptr);
//        }
//
//        crypto_context.reset();
//        {
//            bool res = remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);
//            INFO("Remove DES key to PROV_RSA_FULL enhanced provider" << get_last_error());
//            REQUIRE(res);
//        }
//    }
}

TEST_CASE("HSM creation crypto context", "[CryptoContext][HSM]") {

    SECTION("key test_griha0001 - no password") {
        Error err_sink;

        //create by provider type
        auto crypto_context = guard(
                CreateCryptoContext(PROVNAME_CRYPTOPRO_HSM_RSA, PROV_CRYPTOPRO_HSM_RSA, CONT_NAME,
                                    nullptr, nullptr, nullptr, &err_sink),
                unknown_deleter);

        {
            INFO("Create by provider type: " << from_wstr(err_sink.message) << get_last_error(err_sink.last_error));
            REQUIRE(err_sink.code == ErrorCode::Success);
            REQUIRE(crypto_context != nullptr);
        }
    }
}
