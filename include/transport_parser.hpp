
#ifndef DATAPACKETS_TRANSPORT_PARSER_HPP
#define DATAPACKETS_TRANSPORT_PARSER_HPP

#include <cstdint>
#include <vector>

namespace DataPackets {

struct TransportPayload {
    bool valid = false;
    std::vector<std::uint8_t> data;
};

TransportPayload extractTransportPayload(
    const std::vector<std::uint8_t>& packet,
    std::uint32_t link_type
);

} // namespace DataPackets

#endif

