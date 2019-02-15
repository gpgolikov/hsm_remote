//
// Created by griha on 09.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_CRYPTO_SESSION_HPP
#define MIKRONSST_HSM_CRYPTO_SESSION_HPP

#include <windows.h>
#include <unknwn.h>

#include "error.hpp"

namespace griha { namespace hsm {

static const GUID IID_ICryptoContext = {0x825346ca, 0xfe0c, 0x4469, {0x9c, 0x56, 0xb3, 0x55, 0x54, 0x7f, 0xa8, 0x85}};
struct ICryptoContext : public IUnknown {
};

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_CRYPTO_SESSION_HPP
