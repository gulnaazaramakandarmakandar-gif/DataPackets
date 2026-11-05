
#ifndef DATAPACKETS_FLOW_TRACKER_HPP
#define DATAPACKETS_FLOW_TRACKER_HPP

#include "packet_parser.hpp"

#include <cstdint>
#include <map>
#include <string>

namespace DataPackets {

struct FlowStats {
    // Overall flow statistics
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;

    // Traffic from canonical endpoint A to endpoint B
    std::uint64_t packets_a_to_b = 0;
    std::uint64_t bytes_a_to_b = 0;

    // Traffic from canonical endpoint B to endpoint A
    std::uint64_t packets_b_to_a = 0;
    std::uint64_t bytes_b_to_a = 0;

    // TCP connection-state observations
    bool syn_seen = false;
    bool syn_ack_seen = false;
    bool handshake_completed = false;
    bool reset_seen = false;
    bool fin_seen = false;
};

class FlowTracker {
public:
    void addPacket(
        const PacketInfo& packet,
        std::uint64_t packet_size
    );

    const std::map<std::string, FlowStats>& getFlows() const;

private:
    std::map<std::string, FlowStats> flows;
};

} // namespace DataPackets

#endif // DATAPACKETS_FLOW_TRACKER_HPP

