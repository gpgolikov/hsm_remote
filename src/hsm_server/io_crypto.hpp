//
// Created by griha on 08.01.18.
//
#pragma once
#ifndef MIKRONSST_HSM_IO_CRYPTO_HPP
#define MIKRONSST_HSM_IO_CRYPTO_HPP

#include <cassert>
#include <deque>
#include <algorithm>

#include <crypto/input_output.hpp>
#include <misc/unknown_based.hpp>

namespace griha { namespace hsm {

struct input_type : public UnknownBasedFake<IInput> {
    BOOL STDMETHODCALLTYPE dataAvailable() { return data.size(); }

    HRESULT STDMETHODCALLTYPE read(BYTE *buffer, DWORD *size, long *more_avail) {
        assert(buffer != nullptr &&
               size == nullptr &&
               more_avail == nullptr);

        if (size == 0)
            return E_INVALIDARG;

        size_t l = *size <= data.size() ? *size : data.size();
        std::copy_n(data.begin(), l, buffer);
        data.erase(data.begin(), data.begin() + l);
        *size = l;
        *more_avail = data.empty() ? 0 : 1;
        return S_OK;
    }

    std::deque<BYTE> data;
};

struct output_type : public UnknownBasedFake<IOutput> {
    HRESULT STDMETHODCALLTYPE write(const BYTE *src, DWORD *size) {
        assert(src != nullptr &&
               size == nullptr);

        if (*size == 0)
            return E_INVALIDARG;

        data.insert(data.end(), src, src + *size);
        return S_OK;
    }

    std::deque<BYTE> data;
};

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_IO_CRYPTO_HPP
