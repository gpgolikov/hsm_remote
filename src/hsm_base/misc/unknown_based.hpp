#pragma once
#ifndef MIKRONSST_HSM_UNKNOWN_HPP
#define MIKRONSST_HSM_UNKNOWN_HPP

#include <windows.h>
#include <unknwn.h>

#include "logger.hpp"

namespace griha { namespace hsm {

template <typename BaseT>
class UnknownBased : public BaseT {

public:
    UnknownBased(GUID guid1,
                 GUID guid2 = IID_IUnknown, GUID guid3 = IID_IUnknown,
                 GUID guid4 = IID_IUnknown, GUID guid5 = IID_IUnknown)
            : guid1_(guid1)
            , guid2_(guid2)
            , guid3_(guid3)
            , guid4_(guid4)
            , guid5_(guid5)
    {}

    virtual ~UnknownBased() {}

    HRESULT STDMETHODCALLTYPE QueryInterface (REFIID riid, LPVOID * ppvObj) {
		if (ppvObj == nullptr)
            return E_INVALIDARG;

        *ppvObj = nullptr;
        if (is_available(riid)) {
            *ppvObj = static_cast<LPVOID>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef()
    {
        InterlockedIncrement(&_ref_counter);
        return static_cast<ULONG>(_ref_counter);
    }

    ULONG STDMETHODCALLTYPE Release()
    {
        InterlockedDecrement(&_ref_counter);
        if (_ref_counter <= 0)
            delete this;

        return static_cast<ULONG>(_ref_counter);
    }

private:
    bool is_available(REFIID riid) const {
		return riid == IID_IUnknown ||
                riid == guid1_ || riid == guid2_ || riid == guid3_ || riid == guid4_ || riid == guid5_;
    }

private:
    LONG _ref_counter {0}; // todo
    GUID guid1_, guid2_, guid3_, guid4_, guid5_;
};

template <typename BaseT>
struct UnknownBasedFake : public BaseT {
    virtual ~UnknownBasedFake() {}
    HRESULT STDMETHODCALLTYPE QueryInterface (REFIID, LPVOID*) { return E_NOINTERFACE; }
    ULONG STDMETHODCALLTYPE AddRef() { return 1; }
    ULONG STDMETHODCALLTYPE Release() { return 1; }
};

inline void unknown_deleter(IUnknown *ptr) {
    ptr->Release();
}

struct unknown_deleter_type {
    void operator() (IUnknown *ptr) { unknown_deleter(ptr); }
};

}} // namespace griha::hsm

#endif