
#ifndef DATAPACKETS_DNS_PARSER_HPP
#define DATAPACKETS_DNS_PARSER_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace DataPackets {

struct DNSQuery {
    bool valid = false;
    bool is_response = false;
    std::string domain;
    std::uint16_t query_type = 0;
};

class DNSParser {
public:
    static DNSQuery parse(
        const std::vector<std::uint8_t>& payload
    );
};

}

#endif
