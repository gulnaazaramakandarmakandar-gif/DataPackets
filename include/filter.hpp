
#ifndef DATAPACKETS_FILTER_HPP
#define DATAPACKETS_FILTER_HPP

#include "packet_parser.hpp"

#include <string>

namespace DataPackets {

struct FilterOptions {
    std::string protocol;
    std::string ip;
    int port = -1;
};

bool matchesFilter(
    const PacketInfo& packet,
    const FilterOptions& filter
);

}

#endif
