#pragma once
#ifndef GUARD_H
#define GUARD_H

#include <memory>
#include <type_traits>

#if (defined (_WIN32) || defined (_WIN64))
#   include <windows.h>
#endif

namespace griha { namespace tools {

namespace detail {

template<typename T> struct functor_arguments_1 {};

template<typename T, typename R, typename Arg>
struct functor_arguments_1<R ( T::* )( Arg )> {
    using result_type = R;
    using type = Arg;
};

template<typename T, typename R, typename Arg>
struct functor_arguments_1<R ( T::* )( Arg ) const> {
    using result_type = R;
    using type = Arg;
};

template<typename T> using functor_arguments_1_type = typename functor_arguments_1<T>::type;

template<typename T, typename FuncDeleter>
struct helper {
//    using U = std::remove_pointer_t<functor_arguments_1_type<decltype( &FuncDeleter::operator() )>>;
//    static_assert(std::is_same<T, U>::value || std::is_void<U>::value ||
//                  (std::is_base_of<U, T>::value && std::has_virtual_destructor<U>::value),
//                  "U should be same as T or void or to be base type of T and have virtual destructor");

    using ptr = std::unique_ptr<std::conditional_t<std::is_pointer<T>::value,
            std::remove_pointer_t<T>, T>, FuncDeleter>;
};

template<typename T, typename R, typename U>
struct helper<T, R( U* )> {
    static_assert(std::is_same<T, U>::value || std::is_void<U>::value ||
                  (std::is_base_of<U, T>::value && std::has_virtual_destructor<U>::value),
                  "U should be same as T or void or base of T and has virtual destructor");

    using ptr = std::unique_ptr<T, R (*)( U* )>;
};

template<typename R, typename T>
struct helper<std::nullptr_t, R( T* )> {
    using ptr = std::unique_ptr<T, R (*)( T* )>;
};

template<typename R, typename T>
struct helper<std::nullptr_t, R (*)( T* )> {
    using ptr = std::unique_ptr<T, R (*)( T* )>;
};

template<typename FuncDeleter>
struct helper<std::nullptr_t, FuncDeleter> {
    using func_args_type = functor_arguments_1_type<decltype( &FuncDeleter::operator() )>;

    using ptr = std::enable_if_t<std::is_pointer<func_args_type>::value,
            std::unique_ptr<std::remove_pointer_t<func_args_type>, FuncDeleter>>;
};

} // namespace detail

template<typename T, typename FuncDeleter = typename std::unique_ptr<T>::deleter_type>
using guard_ptr = typename detail::helper<T, FuncDeleter>::ptr;

template<typename FuncDeleter>
constexpr decltype(auto) guard( std::nullptr_t pointer, FuncDeleter fn ) {
    return guard_ptr<std::nullptr_t, FuncDeleter>( pointer, fn );
}

template<typename T, typename FuncDeleter = typename std::unique_ptr<T>::deleter_type>
constexpr decltype(auto) guard( T* pointer, FuncDeleter fn = FuncDeleter() ) {
    return guard_ptr<T, FuncDeleter>( pointer, fn );
}

#if (defined (_WIN32) || defined (_WIN64))

template<typename FuncDeleter>
constexpr decltype(auto) guard( ULONG_PTR pointer, FuncDeleter fn ) {
    return guard<void>(ULongToPtr(pointer), [fn](void* ptr) { fn(PtrToUlong(ptr)); });
}

template<typename FuncDeleter>
constexpr decltype(auto) guard( LONG_PTR pointer, FuncDeleter fn ) {
    return guard<void>(LongToPtr(pointer), [fn](void* ptr) { fn(PtrToLong(ptr)); });
}

#endif

}} // namespace griha::tools

#endif // GUARD_H
