//
// Created by griha on 24.12.17.
//
#include <catch.hpp>

#include <array>

#include <windows.h>

#include <griha/tools/guard.hpp>
#include <griha/tools/hexadecimal.hpp>

#include <crypto_win_base.hpp>

#include "common.hpp"

using namespace griha::hsm;
using namespace griha::hsm::tools;
using namespace griha::tools;

TEST_CASE("RSA encrypt on private key", "[Cipher_RnD][RnD][noHSM]") {

    SECTION("export generated RSA key pair") {
        remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);

        HCRYPTPROV h_prov {0};
        auto res = CryptAcquireContext(&h_prov, CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
        INFO("CryptAcquireContext: error occurred while new keyset has being been created" << get_last_error());
        REQUIRE(res == TRUE);

        auto h_prov_guard = guard(h_prov, safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0)));

        HCRYPTKEY h_key {0};
        res = CryptGenKey(h_prov, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &h_key);
        INFO("CryptGenKey: error while key pair has being been generated");
        REQUIRE(res == TRUE);

        auto h_key_guard = guard(h_key, safed_deleter(CryptDestroyKey));

        std::vector<uint8_t> buffer;
        DWORD sz = 4096;
        buffer.resize(sz, 0);
        res = CryptExportKey(h_key, 0, PRIVATEKEYBLOB, 0, buffer.data(), &sz);
        INFO("CryptExportKey: error while private blob has being been exported" << get_last_error());
        REQUIRE(res == TRUE);

        WARN("Exported private key blob: " << as_hex_n(buffer.begin(), sz));

        sz = 4096;
        buffer.resize(sz, 0);
        res = CryptExportKey(h_key, 0, PUBLICKEYBLOB, 0, buffer.data(), &sz);
        INFO("CryptExportKey: error while public blob has being been exported" << get_last_error());
        REQUIRE(res == TRUE);

        WARN("Exported public key blob: " << as_hex_n(buffer.begin(), sz));

// 0702000000A40000
// 52534132 - RSA2
// 00040000 - 1024 key len
// 01000100 - pub exp
// module
// EB3B5CDA88EFB4C034BE749A32EE30E7164BA9F3FA6DEB54D17BF9D6EB9A8DF46BDE44734C0B52DA32A7D0D6591562D61C1EA538B1D3C7E81D42D1D846DA410366A25570951FF819981A34A8BC5245AC735E8574DA65E1172595C1671B862F98E12C0AF90DE34AEBF3488F7C170AEBDDC13FB435FFA31E67016A88DEC389DFB3
// 536B115D0B99D620DEE228BEF2832EA892D515276E65BD8DB91C60D101D4CC0071331F3882AD14D29CC13F3FC9D3F37DE4B67B89A29992597AD9D274D16912E1
// 09F229BF2943FE840074EE1D308CF8544744BA088272BDE9E76626E609EC9453E68495201D22349F5AB063372672D727E1F7C89F2662D5D373E0DBC25E1F97CC
// 01FFBEB702C04CB8B90759A3FC10888C64C8DB068CB51297CF835460FAE5ACB862032FDD2AF17D8ECFE6714D674E9828B80D0531614658047645079262CBCF9D
// D928DC6B8CFA76664B1A487D41276135CAD7A04D18734A52ABD60AC6253C7F4379BD33F0F3342B4422263CF1E85688E90B4C3420EAAD8BA5DADC09C71E3CC669
// FCB7FF97C9A9081A00271FD365446B65BA88E84463E8F8F2FF31906AE482F9E45992F3F379B9D5C93E8F28A5D06B31D60238F4515849B71FA6A2287DA9CA5508
// private exp
// E1AF967963DD9A9D89A13D2E26360892583824EDC5C2C128A8020A58B1A913770D94FD787CBA6D65EFC65D9A64999BDBE86D3BBF00C2F57E84798BC6BA7BA815640CC7AD10D60DB5B1C3EE62D9772A79A2776403CD315F1B2DE988145EFB7FBFA60F58760D78B5C21FC4FFA93F70F68C336915EF7698D6D1C94193368A68FC63

// 0602000000A40000
// 52534131 - RSA1
// 00040000 - 1024 key len
// 01000100 - pub exp
// module
// EB3B5CDA88EFB4C034BE749A32EE30E7164BA9F3FA6DEB54D17BF9D6EB9A8DF46BDE44734C0B52DA32A7D0D6591562D61C1EA538B1D3C7E81D42D1D846DA410366A25570951FF819981A34A8BC5245AC735E8574DA65E1172595C1671B862F98E12C0AF90DE34AEBF3488F7C170AEBDDC13FB435FFA31E67016A88DEC389DFB3

    }

//    SECTION("pre-generated key pair") {
//        PUBLICKEYSTRUC
//    }
}

TEST_CASE("RSA encrypt on private key - HSM", "[Cipher_RnD][RnD][HSM]") {

    HCRYPTPROV h_prov_trans{0};
    auto res = CryptAcquireContext(&h_prov_trans, CONT_NAME_TRANS, PROVNAME_CRYPTOPRO_HSM_RSA, PROV_CRYPTOPRO_HSM_RSA, 0);
    INFO("Create container error: " << get_last_error());
    REQUIRE(res == TRUE);

    auto h_prov_trans_guard = guard(h_prov_trans, safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0)));

    HCRYPTKEY h_key_trans{0};
    res = CryptGetUserKey(h_prov_trans, AT_KEYEXCHANGE, &h_key_trans) ||
            CryptGetUserKey(h_prov_trans, AT_SIGNATURE, &h_key_trans);
    INFO("Importing DES transport key error " << get_last_error());
    REQUIRE(res == TRUE);

    auto h_key_trans_guard = guard(h_key_trans, safed_deleter(CryptDestroyKey));

    SECTION("export existing RSA key pair") {
        HCRYPTPROV h_prov {0};
        res = CryptAcquireContext(&h_prov, CONT_NAME, PROVNAME_CRYPTOPRO_HSM_RSA, PROV_CRYPTOPRO_HSM_RSA, 0);
        INFO("CryptAcquireContext: error occurred when crypto context has been required" << get_last_error());
        REQUIRE(res == TRUE);

        auto h_prov_guard = guard(h_prov, safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0)));

        HCRYPTKEY h_key {0};
        res = CryptGetUserKey(h_prov, AT_KEYEXCHANGE, &h_key);
        INFO("CryptGetUserKey: error when key pair has been required" << get_last_error());
        REQUIRE(res == TRUE);

        auto h_key_guard = guard(h_key, safed_deleter(CryptDestroyKey));

        std::array<uint8_t, 4096> buffer = {0};
        DWORD sz = buffer.size();
        res = CryptExportKey(h_key, h_key_trans, PRIVATEKEYBLOB, 0, buffer.data(), &sz);
        INFO("CryptExportKey: error while private blob has being been exported" << get_last_error());
        CHECK(res == TRUE);
        if (res) {
            WARN("Exported private key blob (encrypted): " << as_hex_n(buffer.begin(), sz));

            sz -= 8;
            res = CryptDecrypt(h_key_trans, 0, TRUE, 0, buffer.data() + 8, &sz);
            INFO("CryptDecrypt: error while decrypt exported private blob" << get_last_error());
            CHECK(res == TRUE);
            if (res)
                WARN("Exported private key blob: " << as_hex_n(buffer.begin(), sz));
        }

        buffer.fill(0); // reset buffer to zero
        res = CryptExportKey(h_key, 0, PUBLICKEYBLOB, 0, buffer.data(), &sz);
        INFO("CryptExportKey: error while public blob has being been exported" << get_last_error());
        CHECK(res == TRUE);
        if (res)
            WARN("Exported public key blob: " << as_hex_n(buffer.begin(), sz));
    }
}