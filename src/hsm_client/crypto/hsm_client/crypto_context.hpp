//
// Created by griha on 13.01.18.
//
#pragma once
#ifndef MIKRONSST_HSM_LIB_CRYPTO_CONTEXT_HPP
#define MIKRONSST_HSM_LIB_CRYPTO_CONTEXT_HPP

#include <cstdint>

#include <crypto/crypto_context.hpp>
#include <crypto/error.hpp>
#include <crypto/input_output.hpp>

namespace griha { namespace hsm {

extern "C" __declspec(dllexport) ICryptoContext*
__cdecl CreateCryptoContext(uint16_t key_id, const char *ip, uint16_t port, IError *err_sink);

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_LIB_CRYPTO_CONTEXT_HPP
