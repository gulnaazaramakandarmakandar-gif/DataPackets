
#include "filter.hpp"

#include <algorithm>
#include <cctype>

namespace DataPackets {

bool matchesFilter(
    const PacketInfo& packet,
    const FilterOptions& filter
) {
    if (!filter.protocol.empty()) {
        std::string requested = filter.protocol;
        std::transform(
            requested.begin(), requested.end(),
            requested.begin(),
            [](unsigned char c) {
                return static_cast<char>(std::toupper(c));
            }
        );

        std::string actual = packet.protocol;
        std::transform(
            actual.begin(), actual.end(),
            actual.begin(),
            [](unsigned char c) {
                return static_cast<char>(std::toupper(c));
            }
        );

        if (actual != requested) {
            return false;
        }
    }

    if (!filter.ip.empty()) {
        if (packet.source_ip != filter.ip &&
            packet.destination_ip != filter.ip) {
            return false;
        }
    }

    if (filter.port >= 0) {
        if (!packet.has_ports ||
            (packet.source_port != filter.port &&
             packet.destination_port != filter.port)) {
            return false;
        }
    }

    return true;
}

}

