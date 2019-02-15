//
// Created by griha on 09.12.17.
//
#include "misc/logger.hpp"

#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>

#include "misc/filesystem.hpp"

namespace griha { namespace hsm {

namespace log = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;
namespace trivial = boost::log::trivial;

const size_t MAX_LINE = 255;

struct StandardLog::Impl {
    src::severity_logger< trivial::severity_level > lg;

    Impl(const std::string &name, bool debug) {
        log::add_file_log(
                keywords::file_name = "hsm_remote_%4N.log",
                keywords::rotation_size = 10 * 1024 * 1024, // 10 MByte
                keywords::target = from_wstr(get_executable_path() + L"\\logs"),
                keywords::max_files = 10,
                keywords::scan_method = sinks::file::scan_matching,
                keywords::auto_flush = true,
                keywords::open_mode = std::ios_base::app | std::ios_base::out,
                keywords::format = "[%TimeStamp%]: %Message%"
        );
        log::add_common_attributes();
    }

    void debug(bool value) {
    }

    void write(LogType type, const std::string &str) {
        switch (type) {
            case LogType::Information:
                BOOST_LOG_SEV(lg, trivial::info) << str;
                break;

            case LogType::Warning:
                BOOST_LOG_SEV(lg, trivial::warning) << "(warning) " << str;
                break;

            case LogType::Error:
                BOOST_LOG_SEV(lg, trivial::error) << "(error) " << str;
                break;

            case LogType::Critical:
                BOOST_LOG_SEV(lg, trivial::fatal) << "(fatal) " << str;
                break;

            case LogType::Debug:
                BOOST_LOG_SEV(lg, trivial::debug) << "(debug) " << str;
                break;
        }
    }
};

StandardLog::StandardLog( const std::string& name, bool debug )
        : _pimpl( new StandardLog::Impl( name, debug ) ), _debug( debug ) {
}

StandardLog::~StandardLog() {
    delete _pimpl;
}

void StandardLog::write( LogType type, const std::string& str ) {
    _pimpl->write(type, str);
}

void StandardLog::debug( bool value ) {
    _pimpl->debug(value);
    _debug = value;
}

}} // namespace griha::hsm
