//
// Created by griha on 07.01.18.
//
#include <catch.hpp>

#include <crypto/crypto_types.hpp>

#include <crypto_win_base.hpp>

#include <griha/tools/hexadecimal.hpp>

#include "common.hpp"

using namespace griha::hsm;
using namespace griha::hsm::tools;
using namespace griha::tools;

TEST_CASE("Utilities - gen key", "[genKeyOnly]") {

    SECTION("key generate") {
        remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);

        {
            bool res = gen_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);
            INFO("Generate user key in PROV_RSA_FULL enhanced provider" << get_last_error());
            REQUIRE(res);
        }
    }
}

TEST_CASE("Utilities - import key", "[importKeyOnly_noHSM]") {

    std::vector<uint8_t> blob = {
            0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00,
            0x52, 0x53, 0x41, 0x32,
            0x00, 0x08, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00,
            0x0b, 0x86, 0x41, 0x33, 0xfa, 0x0b, 0xd3, 0x2b, 0xff, 0xef, 0xf1, 0x3c, 0x03, 0xdf, 0xd6, 0x70, 0xc8, 0x0b,
            0x6a, 0xdd, 0xa5, 0x73, 0x78, 0x84, 0x18, 0x6e, 0xab, 0xfb, 0xca, 0x22, 0x34, 0xa1, 0x6f, 0x3c, 0xda, 0x98,
            0x5b, 0x59, 0x6a, 0x03, 0x1f, 0x62, 0x74, 0x7e, 0x0d, 0x4f, 0x14, 0x0e, 0x08, 0xee, 0x10, 0x0a, 0xe5, 0xc7,
            0x83, 0x9d, 0x3c, 0xd1, 0xef, 0xc2, 0xaa, 0x2a, 0xc7, 0x65, 0x6d, 0x39, 0x8a, 0x46, 0x08, 0xcc, 0x74, 0x22,
            0x14, 0x5c, 0x52, 0x01, 0xa7, 0x1d, 0x21, 0xe8, 0xb8, 0x3f, 0x54, 0x13, 0xdd, 0x98, 0x88, 0xd4, 0x44, 0x91,
            0x15, 0x70, 0xee, 0xae, 0x74, 0x83, 0xca, 0x83, 0xba, 0x47, 0x0a, 0xac, 0x33, 0x0a, 0x8a, 0x06, 0xec, 0x27,
            0xa8, 0xe7, 0x07, 0xd1, 0x48, 0x6d, 0xe4, 0xda, 0x50, 0x48, 0xf7, 0x03, 0xf2, 0x3c, 0x68, 0xc7, 0x14, 0x77,
            0xf0, 0x82, 0x1d, 0x0e, 0x5b, 0x3a, 0x4e, 0xea, 0xa3, 0x53, 0x5d, 0x47, 0x63, 0x70, 0x74, 0xda, 0x74, 0x22,
            0x89, 0x17, 0xff, 0x96, 0x44, 0x0f, 0xd2, 0xc7, 0xcc, 0x0c, 0x0e, 0x00, 0x08, 0x6c, 0x72, 0xca, 0x04, 0x85,
            0xb2, 0x19, 0x67, 0x6e, 0x5c, 0x24, 0x42, 0x34, 0x04, 0x44, 0x37, 0xf0, 0x37, 0x27, 0x1a, 0x0c, 0xec, 0xa2,
            0x4a, 0xd1, 0xab, 0xa1, 0xe8, 0x61, 0x55, 0x5e, 0xb8, 0xaa, 0x2e, 0xf6, 0x48, 0xfe, 0x70, 0x31, 0xca, 0x59,
            0xd6, 0x80, 0x03, 0xaf, 0x4f, 0x1a, 0x0d, 0x8d, 0xe7, 0x1a, 0xac, 0x26, 0xcf, 0x4b, 0xfc, 0xcf, 0x4f, 0xb6,
            0x7e, 0xa9, 0xa0, 0x30, 0x60, 0xc6, 0x83, 0xee, 0x9f, 0x1a, 0xca, 0xb6, 0x32, 0xd7, 0x27, 0xc0, 0x10, 0xef,
            0x0d, 0x1d, 0xac, 0xde, 0xec, 0x9f, 0xd3, 0xe9, 0xe9, 0xe8, 0xbc, 0xab, 0xb1, 0xc8, 0x9f, 0x79, 0xf4, 0x03,
            0xce, 0xe7, 0x2f, 0x1e,
            0x37, 0xbb, 0x0e, 0xfd, 0x9a, 0x20, 0x85, 0x7c, 0x34, 0x8a, 0xcb, 0x4c, 0x86, 0x9c, 0x4c, 0xe9, 0xfa, 0x49,
            0xb4, 0xcd, 0x5e, 0x96, 0x43, 0x0b, 0xf3, 0x38, 0x62, 0xa1, 0xe5, 0x39, 0x79, 0x87, 0x90, 0x1c, 0xa9, 0x1d,
            0x2c, 0x2c, 0x5d, 0x0e, 0x2b, 0x55, 0x09, 0xbb, 0x4f, 0x1a, 0x61, 0x41, 0xe5, 0xd5, 0x40, 0x20, 0x4c, 0xaa,
            0xf2, 0xf2, 0x48, 0xe3, 0x6b, 0x5e, 0xe1, 0xac, 0x67, 0x51, 0xdb, 0xd7, 0x5b, 0x28, 0x11, 0xbc, 0xe3, 0xee,
            0x4a, 0x67, 0x1f, 0xfd, 0x6d, 0xe9, 0x1c, 0xe6, 0xfb, 0xce, 0x44, 0xad, 0xa4, 0xf9, 0x37, 0x68, 0xd3, 0x41,
            0x3a, 0xbc, 0x60, 0x75, 0x22, 0x8a, 0xde, 0xd9, 0x99, 0xa2, 0x06, 0x06, 0xd5, 0xeb, 0x2f, 0xe0, 0xf7, 0x77,
            0x9a, 0xb1, 0x8b, 0x00, 0xa2, 0x4a, 0x7f, 0x69, 0xe6, 0x5c, 0x61, 0xcc, 0x08, 0x2c, 0x67, 0x75, 0x62, 0x58,
            0x03, 0xa2,
            0x4a, 0xb7, 0xc0, 0x14, 0xdd, 0x03, 0xd6, 0x30, 0xd7, 0x75, 0x0b, 0x27, 0xf7, 0xbd, 0x78, 0x4a, 0x9e, 0x0e,
            0x7d, 0xf0, 0x4d, 0x88, 0x3e, 0xb2, 0xb1, 0x52, 0xac, 0xba, 0xc6, 0xae, 0xab, 0xd0, 0xf0, 0x84, 0xc1, 0x81,
            0x52, 0x5f, 0xb6, 0x7a, 0x57, 0xc5, 0x29, 0x7c, 0xbe, 0x97, 0x80, 0x77, 0x04, 0xf4, 0xc3, 0x56, 0x83, 0xf0,
            0x40, 0x14, 0xa6, 0x0d, 0xcc, 0xfd, 0xeb, 0xef, 0xfa, 0x32, 0x8b, 0x47, 0xfb, 0xdf, 0xbb, 0xdd, 0x98, 0x7b,
            0xde, 0xe1, 0xf5, 0x6d, 0x1a, 0x4b, 0x58, 0x64, 0x39, 0xb8, 0xcd, 0x47, 0x0c, 0x90, 0xc7, 0xce, 0xc4, 0x7a,
            0xd1, 0x0e, 0xbf, 0x1d, 0x34, 0xc5, 0x4b, 0x1e, 0x71, 0x1c, 0x7f, 0x8b, 0x0e, 0xec, 0xd0, 0x33, 0xaa, 0x50,
            0xe0, 0x8d, 0x5e, 0x80, 0x58, 0xaf, 0xa9, 0x1c, 0x4f, 0x2d, 0xa0, 0x7f, 0x9e, 0xd4, 0x3f, 0xb4, 0xb6, 0x1a,
            0x65, 0x11,
            0x92, 0x90, 0xa7, 0x3b, 0x25, 0x9d, 0xe2, 0xae, 0x46, 0xb0, 0xc6, 0x92, 0xa8, 0xe8, 0x9f, 0x85, 0xc1, 0x93,
            0xf8, 0x48, 0xe5, 0x1a, 0x6c, 0xa4, 0x9d, 0xd4, 0x11, 0xce, 0x03, 0xbc, 0x09, 0xb3, 0x34, 0xa3, 0xb2, 0xe6,
            0x99, 0xac, 0xbe, 0x98, 0xf7, 0x19, 0x07, 0x1b, 0x79, 0x7c, 0x53, 0x97, 0x88, 0xa5, 0xcf, 0xb9, 0xb3, 0x35,
            0x28, 0x16, 0xba, 0xd9, 0xaf, 0x18, 0x60, 0xad, 0x2c, 0x91, 0x53, 0x4f, 0x66, 0xbd, 0x64, 0x99, 0xc4, 0x7f,
            0x0e, 0xbb, 0x48, 0xfd, 0x49, 0x97, 0x58, 0x76, 0xbd, 0xe8, 0xa0, 0x10, 0xe7, 0x22, 0x53, 0x02, 0x52, 0x29,
            0x18, 0x08, 0x6b, 0x5c, 0x40, 0xa0, 0x5d, 0x29, 0xd1, 0xf2, 0x05, 0x98, 0x37, 0xe0, 0x56, 0xd8, 0x9d, 0xcf,
            0x58, 0x46, 0xf3, 0x55, 0x3f, 0x3a, 0x98, 0x10, 0x75, 0x79, 0x7e, 0x00, 0x32, 0x49, 0xf6, 0x7e, 0x19, 0xbf,
            0x61, 0xeb,
            0x85, 0x34, 0x04, 0xca, 0x17, 0x6c, 0x53, 0x0a, 0x59, 0xaa, 0x1b, 0x09, 0x48, 0x58, 0xd2, 0x70, 0x7e, 0x8e,
            0x34, 0x05, 0xc6, 0x33, 0xf8, 0xef, 0x01, 0xe4, 0x18, 0x82, 0xcc, 0xd1, 0x27, 0xaf, 0x65, 0x37, 0x09, 0x24,
            0xa3, 0xa1, 0xff, 0x24, 0xf5, 0x12, 0xe2, 0xca, 0x55, 0xb0, 0x31, 0x28, 0xbb, 0x8f, 0x91, 0x5e, 0x6e, 0xaf,
            0x73, 0x20, 0x76, 0x6a, 0xec, 0x1b, 0x23, 0x8a, 0xeb, 0xbf, 0x6c, 0xf0, 0xb6, 0xa8, 0x07, 0xa8, 0x97, 0x7d,
            0xc2, 0x85, 0x88, 0x13, 0x09, 0x63, 0x10, 0x21, 0x5a, 0x3b, 0xb5, 0x4e, 0x3e, 0x1d, 0x52, 0x4e, 0x5f, 0xe3,
            0x4f, 0x23, 0x52, 0xd1, 0xd4, 0x8e, 0x8a, 0x2c, 0x90, 0x21, 0x05, 0x78, 0x43, 0x24, 0x9d, 0xbd, 0x40, 0x48,
            0x7f, 0x57, 0xc9, 0xa9, 0x3d, 0x78, 0x98, 0xab, 0x1f, 0xdf, 0xd7, 0x14, 0x96, 0xa5, 0xd8, 0x04, 0x72, 0xc0,
            0xf1, 0xc3,
            0x99, 0x67, 0x2a, 0x99, 0xf9, 0xb7, 0xa3, 0xac, 0x4d, 0xa4, 0x1b, 0xf8, 0xb3, 0xd9, 0x0b, 0xff, 0x79, 0x51,
            0xb1, 0x6c, 0x27, 0xa8, 0x8e, 0xa4, 0x5c, 0x4c, 0xf3, 0xbf, 0x26, 0x79, 0xbd, 0xd5, 0x19, 0xa2, 0xed, 0x43,
            0x3a, 0xbb, 0xc9, 0xc1, 0x8e, 0x0a, 0x0b, 0x01, 0x0c, 0x58, 0x1f, 0x2f, 0x08, 0x5e, 0x3d, 0x18, 0xdb, 0x4f,
            0x94, 0x51, 0xeb, 0xc3, 0x2d, 0x0b, 0x66, 0x8f, 0xf7, 0x2d, 0x46, 0x42, 0xc4, 0x47, 0x7c, 0xfd, 0x8f, 0x4f,
            0x04, 0x01, 0xfa, 0x91, 0x98, 0xd1, 0x22, 0x93, 0x00, 0x0e, 0x2f, 0x65, 0xb7, 0x3f, 0x79, 0xac, 0xc6, 0x51,
            0xf9, 0x2c, 0x58, 0x21, 0x29, 0xf3, 0x06, 0xb4, 0x71, 0xb1, 0x94, 0x8a, 0xfa, 0x03, 0x2d, 0x12, 0x0c, 0x27,
            0x83, 0x6d, 0xe7, 0x6a, 0x6d, 0x9f, 0x6d, 0xdf, 0xb8, 0x48, 0xda, 0x62, 0x1b, 0x92, 0x5c, 0xbd, 0x74, 0x17,
            0x1b, 0xd3,
            0xae, 0x84, 0x7a, 0x7b, 0x87, 0x6c, 0x70, 0xa2, 0x04, 0x74, 0xe8, 0x5a, 0xce, 0x33, 0x17, 0xed, 0xad, 0x02,
            0xf6, 0x3d, 0x29, 0x0c, 0x5a, 0x0f, 0xe8, 0x41, 0xdc, 0xba, 0x60, 0xa8, 0x76, 0x98, 0x47, 0xe3, 0xae, 0xb7,
            0x7a, 0x92, 0x84, 0x53, 0x42, 0x2f, 0x62, 0x6b, 0x89, 0x67, 0xa2, 0x4d, 0x07, 0x0c, 0x26, 0xab, 0x27, 0xf7,
            0xe6, 0x62, 0xeb, 0x42, 0x2c, 0xf9, 0x37, 0xd2, 0xed, 0xbe, 0xfc, 0x17, 0xb2, 0x01, 0xc9, 0x8b, 0x89, 0x95,
            0x47, 0x46, 0x13, 0x8b, 0x45, 0x24, 0xb1, 0xba, 0xa8, 0x86, 0x82, 0x07, 0x9a, 0x5a, 0xb1, 0x61, 0xd1, 0x18,
            0x7c, 0xfc, 0x1e, 0x8a, 0xc2, 0x8f, 0x5d, 0x7a, 0xe8, 0x74, 0x38, 0xe3, 0xe6, 0x40, 0x17, 0x47, 0xf3, 0xe3,
            0x4f, 0x4d, 0x30, 0xbe, 0xcd, 0xb2, 0xd6, 0x45, 0x79, 0x67, 0xa3, 0xc4, 0x12, 0x2b, 0xae, 0x49, 0x08, 0x2f,
            0x9d, 0xff, 0x2b, 0x7e, 0x55, 0x74, 0x39, 0xf9, 0x77, 0xc2, 0xb2, 0x95, 0xe1, 0x22, 0x1c, 0x54, 0xba, 0x34,
            0xae, 0x83, 0x14, 0x58, 0x27, 0x6c, 0x9d, 0xa0, 0x6a, 0x15, 0x35, 0x11, 0x6a, 0x6f, 0xbe, 0xc7, 0x71, 0x2f,
            0x4d, 0x4a, 0xde, 0xf3, 0x2e, 0x39, 0x45, 0x82, 0x44, 0xa9, 0xc1, 0x46, 0xf2, 0xad, 0x5e, 0xfb, 0xce, 0x3e,
            0x76, 0xe9, 0x87, 0x2c, 0x94, 0x01, 0xb2, 0x89, 0xc1, 0x06, 0xd8, 0x3f, 0xda, 0x01, 0x5a, 0x30, 0x57, 0xce,
            0x93, 0x8f, 0x73, 0xc5, 0x4e, 0x57, 0xa6, 0xd2, 0xca, 0x0c, 0x85, 0x1b, 0x36, 0xfe, 0x68, 0xf6, 0xca, 0xee,
            0xe4, 0x44, 0x32, 0xbe, 0x7b, 0x94, 0xd2, 0xe7, 0xfd, 0xc0, 0x52, 0xb2, 0xe4, 0x00, 0xd0, 0xeb, 0xfb, 0x96,
            0x04, 0xb0, 0x9c, 0xa3, 0x33, 0xf2, 0x04, 0x6f, 0x0a, 0xe8, 0xcb, 0xb1, 0x89, 0xb4, 0x9c, 0xe0, 0xdb, 0xbd,
            0x0c, 0xa1, 0x79, 0x9e,
    };

    remove_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL);

    {
        bool res = import_user_key(CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL, blob.begin(), blob.size());
        INFO("Generate user key in PROV_RSA_FULL enhanced provider" << get_last_error());
        REQUIRE(res);
    }
}

TEST_CASE("Utilities - export key", "[exportKeyOnly_noHSM]") {

    HCRYPTPROV h_prov{0};
    auto res = CryptAcquireContext(&h_prov, CONT_NAME, MS_ENHANCED_PROV, PROV_RSA_FULL, 0);
    INFO("CryptAcquireContext: error occurred when crypto context has been required" << get_last_error());
    REQUIRE(res == TRUE);

    auto h_prov_guard = guard(h_prov, safed_deleter(std::bind(&CryptReleaseContext, std::placeholders::_1, 0)));

    HCRYPTKEY h_key{0};
    res = CryptGetUserKey(h_prov, AT_KEYEXCHANGE, &h_key);
    INFO("CryptGetUserKey: error when key pair has been required" << get_last_error());
    REQUIRE(res == TRUE);

    auto h_key_guard = guard(h_key, safed_deleter(CryptDestroyKey));

    std::array<uint8_t, 4096> buffer = {0};
    DWORD sz = buffer.size();
    res = CryptExportKey(h_key, 0, PRIVATEKEYBLOB, 0, buffer.data(), &sz);
    INFO("CryptExportKey: error while private blob has being been exported" << get_last_error());
    CHECK(res == TRUE);
    if (res) {
        WARN("Exported private key blob (little-endian): " << as_hex_n(buffer.begin(), sz));

        std::vector<uint8_t> blob;
        blob.assign(buffer.begin(), buffer.end());

        uint32_t key_size = *(reinterpret_cast<uint32_t*>(blob.data() + 12)) / 8;
        WARN("Key size " << key_size << " bytes");

        size_t o = 12;
        std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // key_size
        o += 4;
        std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // E
        WARN("Exponent: " << as_hex_n(buffer.begin() + o, 4));
        o += 4;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size, buffer.data() + o); // module
        WARN("Module: " << as_hex_n(buffer.begin() + o, key_size));
        o += key_size;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // P
        WARN("P: " << as_hex_n(buffer.begin() + o, key_size / 2));
        o += key_size / 2;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // Q
        WARN("Q: " << as_hex_n(buffer.begin() + o, key_size / 2));
        o += key_size / 2;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // DP
        WARN("DP: " << as_hex_n(buffer.begin() + o, key_size / 2));
        o += key_size / 2;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // DQ
        WARN("DQ: " << as_hex_n(buffer.begin() + o, key_size / 2));
        o += key_size / 2;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // InverseQ
        WARN("InverseQ: " << as_hex_n(buffer.begin() + o, key_size / 2));
        o += key_size / 2;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size, buffer.data() + o); // D
        WARN("D: " << as_hex_n(buffer.begin() + o, key_size));

        WARN("Exported private key blob (big-endian): " << as_hex_n(buffer.begin(), sz));
    }

    buffer.fill(0); // reset buffer to zero
    res = CryptExportKey(h_key, 0, PUBLICKEYBLOB, 0, buffer.data(), &sz);
    INFO("CryptExportKey: error while public blob has being been exported" << get_last_error());
    CHECK(res == TRUE);
    if (res) {
        WARN("Exported public key blob (little-endian): " << as_hex_n(buffer.begin(), sz));

        std::vector<uint8_t> blob;
        blob.assign(buffer.begin(), buffer.end());

        uint32_t key_size = *(reinterpret_cast<uint32_t*>(blob.data() + 12)) / 8;
        WARN("Key size " << key_size << " bytes");

        size_t o = 12;
        std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // key_size
        o += 4;
        std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // E
        WARN("Exponent: " << as_hex_n(buffer.begin() + o, 4));
        o += 4;
        std::reverse_copy(blob.data() + o, blob.data() + o + key_size, buffer.data() + o); // module
        WARN("Module: " << as_hex_n(buffer.begin() + o, key_size));

        WARN("Exported public key blob (big-endian): " << as_hex_n(buffer.begin(), sz));
    }
}

TEST_CASE("Utilities - export key from HSM", "[exportKeyOnly_HSM]") {

    HCRYPTPROV h_prov_trans{0};
    auto res = CryptAcquireContext(&h_prov_trans, L"test_trans_3des0001", PROVNAME_CRYPTOPRO_HSM_RSA, PROV_RSA_FULL, 0);
//    auto res = CryptAcquireContext(&h_prov_trans, CONT_NAME_TRANS, PROVNAME_CRYPTOPRO_HSM_RSA, PROV_RSA_FULL, 0);
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
        res = CryptAcquireContext(&h_prov, L"test_rsa_2560001", PROVNAME_CRYPTOPRO_HSM_RSA, PROV_RSA_FULL, 0);
//        res = CryptAcquireContext(&h_prov, CONT_NAME, PROVNAME_CRYPTOPRO_HSM_RSA, PROV_RSA_FULL, 0);
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
            if (res) {
                WARN("Exported private key blob (little-endian): " << as_hex_n(buffer.begin(), sz + 8));

                std::vector<uint8_t> blob;
                blob.assign(buffer.begin(), buffer.end());

                uint32_t key_size = *(reinterpret_cast<uint32_t*>(blob.data() + 12)) / 8;
                WARN("Key size " << key_size);

                size_t o = 12;
                std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // key_size
                o += 4;
                std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // E
                WARN("Exponent: " << as_hex_n(buffer.begin() + o, 4));
                o += 4;
                std::reverse_copy(blob.data() + o, blob.data() + o + key_size, buffer.data() + o); // module
                WARN("Module: " << as_hex_n(buffer.begin() + o, key_size));
                o += key_size;
                std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // P
                WARN("P: " << as_hex_n(buffer.begin() + o, key_size / 2));
                o += key_size / 2;
                std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // Q
                WARN("Q: " << as_hex_n(buffer.begin() + o, key_size / 2));
                o += key_size / 2;
                std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // DP
                WARN("DP: " << as_hex_n(buffer.begin() + o, key_size / 2));
                o += key_size / 2;
                std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // DQ
                WARN("DQ: " << as_hex_n(buffer.begin() + o, key_size / 2));
                o += key_size / 2;
                std::reverse_copy(blob.data() + o, blob.data() + o + key_size / 2, buffer.data() + o); // InverseQ
                WARN("InverseQ: " << as_hex_n(buffer.begin() + o, key_size / 2));
                o += key_size / 2;
                std::reverse_copy(blob.data() + o, blob.data() + o + key_size, buffer.data() + o); // D
                WARN("D: " << as_hex_n(buffer.begin() + o, key_size));

                WARN("Exported private key blob (big-endian): " << as_hex_n(buffer.begin(), sz + 8));
            }
        }

        buffer.fill(0); // reset buffer to zero
        res = CryptExportKey(h_key, 0, PUBLICKEYBLOB, 0, buffer.data(), &sz);
        INFO("CryptExportKey: error while public blob has being been exported" << get_last_error());
        CHECK(res == TRUE);
        if (res) {
            WARN("Exported public key blob (little-endian): " << as_hex_n(buffer.begin(), sz));

            std::vector<uint8_t> blob;
            blob.assign(buffer.begin(), buffer.end());

            uint32_t key_size = *(reinterpret_cast<uint32_t*>(blob.data() + 12)) / 8;
            WARN("Key size " << key_size);

            size_t o = 12;
            std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // key_size
            o += 4;
            std::reverse_copy(blob.data() + o, blob.data() + o + 4, buffer.data() + o); // E
            WARN("Exponent: " << as_hex_n(buffer.begin() + o, 4));
            o += 4;
            std::reverse_copy(blob.data() + o, blob.data() + o + key_size, buffer.data() + o); // module
            WARN("Module: " << as_hex_n(buffer.begin() + o, key_size));

            WARN("Exported public key blob (big-endian): " << as_hex_n(buffer.begin(), sz));
        }
    }
}