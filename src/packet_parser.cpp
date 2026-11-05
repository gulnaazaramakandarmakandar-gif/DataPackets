

#include "packet_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace DataPackets {
namespace {

std::uint16_t read16(
    const std::vector<std::uint8_t>& packet,
    std::size_t offset
) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(packet[offset]) << 8) |
        packet[offset + 1]
    );
}

std::string ipv4ToString(
    const std::vector<std::uint8_t>& packet,
    std::size_t offset
) {
    return std::to_string(packet[offset]) + "." +
           std::to_string(packet[offset + 1]) + "." +
           std::to_string(packet[offset + 2]) + "." +
           std::to_string(packet[offset + 3]);
}

} // namespace

PacketInfo PacketParser::parse(
    const std::vector<std::uint8_t>& packet,
    std::uint32_t link_type
) {
    PacketInfo info;

    // Ethernet link type.
    constexpr std::uint32_t ETHERNET = 1;

    if (link_type != ETHERNET) {
        return info;
    }

    // Minimum Ethernet header: 14 bytes.
    if (packet.size() < 14) {
        return info;
    }

    std::size_t ip_offset = 14;
    std::uint16_t ether_type = read16(packet, 12);

    // Support one VLAN tag.
    if (ether_type == 0x8100 || ether_type == 0x88A8) {
        if (packet.size() < 18) {
            return info;
        }

        ether_type = read16(packet, 16);
        ip_offset = 18;
    }

    // Only process IPv4.
    if (ether_type != 0x0800) {
        return info;
    }

    // Minimum IPv4 header: 20 bytes.
    if (packet.size() < ip_offset + 20) {
        return info;
    }

    const std::uint8_t version_ihl = packet[ip_offset];
    const std::uint8_t version = version_ihl >> 4;

    const std::size_t ip_header_length =
        static_cast<std::size_t>(version_ihl & 0x0F) * 4;

    if (version != 4 || ip_header_length < 20) {
        return info;
    }

    if (packet.size() < ip_offset + ip_header_length) {
        return info;
    }

    const std::uint16_t total_length =
        read16(packet, ip_offset + 2);

    if (total_length < ip_header_length ||
        total_length > packet.size() - ip_offset) {
        return info;
    }

    info.is_ipv4 = true;

    info.source_ip = ipv4ToString(packet, ip_offset + 12);
    info.destination_ip = ipv4ToString(packet, ip_offset + 16);

    const std::uint8_t protocol_number =
        packet[ip_offset + 9];

    info.protocol_number = protocol_number;

    // Check IPv4 fragmentation.
    const std::uint16_t fragment_field =
        read16(packet, ip_offset + 6);

    const std::uint16_t fragment_offset =
        fragment_field & 0x1FFF;

    const bool more_fragments =
        (fragment_field & 0x2000) != 0;

    if (fragment_offset != 0) {
        if (protocol_number == 6) {
            info.protocol = "TCP";
        } else if (protocol_number == 17) {
            info.protocol = "UDP";
        } else if (protocol_number == 1) {
            info.protocol = "ICMP";
        }

        return info;
    }

    const std::size_t ip_end = ip_offset + total_length;

    const std::size_t transport_offset =
        ip_offset + ip_header_length;

    const std::size_t transport_length =
        ip_end - transport_offset;

    // TCP.
    if (protocol_number == 6) {
        info.protocol = "TCP";

        if (transport_length < 20) {
            return info;
        }

        const std::uint16_t source_port =
            read16(packet, transport_offset);

        const std::uint16_t destination_port =
            read16(packet, transport_offset + 2);

        const std::size_t tcp_header_length =
            static_cast<std::size_t>(
                packet[transport_offset + 12] >> 4
            ) * 4;

        if (tcp_header_length < 20 ||
            tcp_header_length > transport_length) {
            return info;
        }

        info.source_port = source_port;
        info.destination_port = destination_port;
        info.has_ports = true;

        // TCP control flags.
        const std::uint8_t flags =
            packet[transport_offset + 13];

        info.tcp_fin = (flags & 0x01) != 0;
        info.tcp_syn = (flags & 0x02) != 0;
        info.tcp_rst = (flags & 0x04) != 0;
        info.tcp_ack = (flags & 0x10) != 0;
    }

    // UDP.
    else if (protocol_number == 17) {
        info.protocol = "UDP";

        if (transport_length < 8) {
            return info;
        }

        const std::uint16_t udp_length =
            read16(packet, transport_offset + 4);

        if (udp_length < 8 ||
            udp_length > transport_length) {
            return info;
        }

        info.source_port =
            read16(packet, transport_offset);

        info.destination_port =
            read16(packet, transport_offset + 2);

        info.has_ports = true;
    }

    // ICMP.
    else if (protocol_number == 1) {
        info.protocol = "ICMP";
    }

    // Other IPv4 protocols.
    else {
        info.protocol = "Other";
    }

    // The first fragment can contain transport flags, but a
    // fragmented datagram is incomplete until reassembly.
    (void)more_fragments;

    return info;
}

} // namespace DataPackets
