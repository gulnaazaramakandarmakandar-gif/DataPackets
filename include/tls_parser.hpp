
#ifndef TLS_PARSER_HPP
#define TLS_PARSER_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace DataPackets {

std::string extractTlsServerName(
    const std::vector<std::uint8_t>& payload
);

}

#endif
