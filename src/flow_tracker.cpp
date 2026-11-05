
#include "flow_tracker.hpp"

#include <algorithm>
#include <utility>

namespace DataPackets {

void FlowTracker::addPacket(
    const PacketInfo& packet,
    std::uint64_t packet_size
) {
    if (!packet.is_ipv4 || !packet.has_ports) {
        return;
    }

    // Identify the source and destination endpoints.
    auto source = std::make_pair(
        packet.source_ip,
        packet.source_port
    );

    auto destination = std::make_pair(
        packet.destination_ip,
        packet.destination_port
    );

    // Canonical ordering keeps both directions in one flow.
    const bool source_is_a = source < destination;

    auto endpoint_a = source;
    auto endpoint_b = destination;

    if (!source_is_a) {
        std::swap(endpoint_a, endpoint_b);
    }

    const std::string key =
        endpoint_a.first + ":" +
        std::to_string(endpoint_a.second) +
        " <-> " +
        endpoint_b.first + ":" +
        std::to_string(endpoint_b.second) +
        " [" + packet.protocol + "]";

    FlowStats& stats = flows[key];

    // Overall statistics.
    ++stats.packets;
    stats.bytes += packet_size;

    // Directional statistics.
    if (source_is_a) {
        ++stats.packets_a_to_b;
        stats.bytes_a_to_b += packet_size;
    } else {
        ++stats.packets_b_to_a;
        stats.bytes_b_to_a += packet_size;
    }

    // Record TCP connection-state observations.
    if (packet.protocol == "TCP") {
        if (packet.tcp_syn && !packet.tcp_ack) {
            stats.syn_seen = true;
        }

        if (packet.tcp_syn && packet.tcp_ack) {
            stats.syn_ack_seen = true;
        }

        if (packet.tcp_ack &&
            stats.syn_seen &&
            stats.syn_ack_seen) {
            stats.handshake_completed = true;
        }

        if (packet.tcp_rst) {
            stats.reset_seen = true;
        }

        if (packet.tcp_fin) {
            stats.fin_seen = true;
        }
    }
}

const std::map<std::string, FlowStats>&
FlowTracker::getFlows() const {
    return flows;
}

} // namespace DataPackets


