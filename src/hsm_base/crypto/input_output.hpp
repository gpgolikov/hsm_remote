//
// Created by griha on 01.12.17.
//
#pragma once
#ifndef MIKRONSST_HSM_INPUT_OUTPUT_HPP
#define MIKRONSST_HSM_INPUT_OUTPUT_HPP

#include <windows.h>
//#include <unknwn.h>

namespace griha { namespace hsm {

static const GUID IID_IInput = {0x9036c524, 0x1e9c, 0x47e2, {0x96, 0x01, 0x89, 0x9f, 0x22, 0x51, 0xea, 0x5b}};
struct IInput : public virtual IUnknown {
    virtual HRESULT STDMETHODCALLTYPE read(BYTE *buffer, DWORD *size, long *more_avail) = 0;
};

static const GUID IID_IOutput = {0x0d3823ff, 0xcbd4, 0x4c76, {0xb3, 0x82, 0xd0, 0xf5, 0x31, 0x89, 0x77, 0x6f}};
struct IOutput : public virtual IUnknown {
    virtual HRESULT STDMETHODCALLTYPE write(const BYTE *data, DWORD *size) = 0;
};

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_INPUT_OUTPUT_HPP
