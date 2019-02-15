//
// Created by griha on 13.01.18.
//
#pragma once
#ifndef MIKRONSST_HSM_FUNCTIONAL_HPP
#define MIKRONSST_HSM_FUNCTIONAL_HPP

#include <crypto/error.hpp>

#include "logger.hpp"
#include "io_manip.hpp"

namespace griha { namespace hsm {

template <typename FnDeleter>
decltype(auto) safed_deleter(FnDeleter fn) {
    return [fn] (ULONG_PTR ptr) {
        DWORD le = ::GetLastError(); // save current error
        if (!fn(ptr))
            LOG_CRITICAL << "safed_deleter: error while handle has being been deleted " << last_error;
        ::SetLastError(le); // restore error
    };
}

}} // namespace griha::hsm

#endif //MIKRONSST_HSM_FUNCTIONAL_HPP
