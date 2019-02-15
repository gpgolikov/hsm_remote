#pragma once
#ifndef HEXADECIMAL_HPP
#define HEXADECIMAL_HPP

#include <sstream>
#include <iomanip>

namespace griha { namespace tools {

template<typename InputIterator, typename CharT = char>
auto as_hex( InputIterator first, InputIterator last, std::basic_string<CharT> delim = "" )
-> std::basic_string<CharT>
{
    using namespace std;

    basic_ostringstream<CharT> os;
    os << hex << setfill( os.widen( '0' ) ) << uppercase;
    for ( ; first != last; ++first )
        os << setw( 2 ) << static_cast<int>( *first ) << delim;

    return os.str();
}

template<typename InputIterator, typename CharT = char>
auto as_hex_n( InputIterator first, typename std::iterator_traits<InputIterator>::difference_type n,
               std::basic_string<CharT> delim = "" )
-> std::basic_string<CharT>
{
    InputIterator last = first;
    std::advance( last, n );

    return as_hex(first, last, delim);
}

}} // namespace griha::tools

#endif //HEXADECIMAL_HPP
