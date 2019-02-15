//
// Created by griha on 29.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_KEYS_HPP
#define MIKRONSST_HSM_KEYS_HPP

#include <cassert>
#include <cstdint>
#include <vector>
#include <algorithm>

#include <windows.h>

#include <griha/tools/hexadecimal.hpp>

#include "crypto_context_impl.hpp"
#include "crypto_win_base.hpp"

namespace griha { namespace hsm {

using namespace griha::hsm::tools;

struct public_key_type {
    HCRYPTKEY h_key {0};
    uint32_t key_size {0}; // bits number
    const uint32_t exp_size {32}; // bits number
    std::vector<uint8_t> key_blob {};

    bool initialize(HCRYPTKEY h_k) {
        assert(h_k && h_key == 0);

        h_key = h_k;
        if (!export_user_key(h_key, 0, true, key_blob))
            return false;

        key_size = *(reinterpret_cast<uint32_t *> (key_blob.data() + 12));

        LOG_DEBUG << "public key has been initialized: size " << key_size << "; public exponent size " << exp_size;
        return true;
    }

    template <typename _OutIter1, typename _OutIter2>
    bool get_key(_OutIter1 n, _OutIter2 e) const {
        uint32_t size = 0;
        std::copy_n(key_blob.rend() - 20, exp_size / 8, e); // little-endian to big-endian format
        std::copy_n(key_blob.rbegin(), key_size / 8, n); // little-endian to big-endian format

        return true;
    }
};

struct private_key_type {
    HCRYPTKEY h_key {0}, h_key_trans {0};
    uint32_t key_size {0}; // bits number
    uint32_t exp_size {0}; // bits number
    std::vector<uint8_t> key_blob {};

    bool initialize(public_key_type &pub_key, HCRYPTKEY h_k_trans) {
        assert(pub_key.h_key && h_key == 0);

        h_key = pub_key.h_key; h_key_trans = h_k_trans;
        if (!export_user_key(h_key, h_key_trans, false, key_blob))
            return false;

        exp_size = key_size = pub_key.key_size;

        LOG_DEBUG << "private key has been initialized: size " << key_size << "; private exponent size " << exp_size;
        return true;
    }

    template <typename _OutIter1, typename _OutIter2>
    bool get_key(_OutIter1 n, _OutIter2 d) const {
        CryptoPP::SecBlock<uint8_t> blob_plain {key_blob.data(), key_blob.size()};

        DWORD sz = blob_plain.size() - 8;
        if (h_key_trans &&
                !CryptDecrypt(h_key_trans, 0, TRUE, 0, blob_plain.data() + 8, &sz)) {
            LOG_ERROR << "private_key_type::get_key: CryptDecrypt error: " << last_error;
            return false;
        }

        blob_plain.resize(sz + 8); // remove encrypted padding

        LOG_DEBUG << "private_key_type::get_key: BLOB has been decrypted";

        uint32_t size = 0;
        std::reverse_copy(blob_plain.begin() + 20, blob_plain.begin() + 20 + key_size / 8, n); // little-endian to big-endian format
        std::reverse_copy(blob_plain.end() - exp_size / 8, blob_plain.end(), d); // little-endian to big-endian format

        return true;
    }
};

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_KEYS_HPP
