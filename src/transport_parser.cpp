
#include "transport_parser.hpp"

#include <cstddef>
#include <cstdint>

namespace DataPackets {
namespace {

bool hasBytes(
    const std::vector<std::uint8_t>& data,
    std::size_t offset,
    std::size_t count)
{
    return offset <= data.size() &&
           count <= data.size() - offset;
}

std::uint16_t read16(
    const std::vector<std::uint8_t>& data,
    std::size_t offset)
{
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[offset]) << 8) |
        static_cast<std::uint16_t>(data[offset + 1]));
}

} // namespace

TransportPayload extractTransportPayload(
    const std::vector<std::uint8_t>& packet,
    std::uint32_t link_type)
{
    TransportPayload result;

    // Ethernet link type.
    if (link_type != 1 || !hasBytes(packet, 0, 14)) {
        return result;
    }

    std::size_t offset = 14;
    std::uint16_t ether_type = read16(packet, 12);

    // Support one VLAN tag.
    if (ether_type == 0x8100 || ether_type == 0x88A8) {
        if (!hasBytes(packet, offset, 4)) {
            return result;
        }

        ether_type = read16(packet, offset + 2);
        offset += 4;
    }

    // IPv4 only.
    if (ether_type != 0x0800 ||
        !hasBytes(packet, offset, 20)) {
        return result;
    }

    const std::uint8_t version_ihl = packet[offset];
    const std::uint8_t version = version_ihl >> 4;
    const std::size_t ip_header_length =
        static_cast<std::size_t>(version_ihl & 0x0F) * 4;

    if (version != 4 ||
        ip_header_length < 20 ||
        !hasBytes(packet, offset, ip_header_length)) {
        return result;
    }

    const std::size_t total_length = read16(packet, offset + 2);

    if (total_length < ip_header_length ||
        !hasBytes(packet, offset, total_length)) {
        return result;
    }

    const std::uint16_t fragment_field = read16(packet, offset + 6);

    // Skip fragmented IPv4 packets; reassembly is not supported.
    if ((fragment_field & 0x3FFF) != 0) {
        return result;
    }

    const std::uint8_t protocol = packet[offset + 9];

    // TCP = 6, UDP = 17.
    if (protocol != 6 && protocol != 17) {
        return result;
    }

    const std::size_t transport_offset =
        offset + ip_header_length;

    const std::size_t ip_payload_length =
        total_length - ip_header_length;

    if (protocol == 6) {
        // TCP header.
        if (ip_payload_length < 20 ||
            !hasBytes(packet, transport_offset, 20)) {
            return result;
        }

        const std::size_t tcp_header_length =
            static_cast<std::size_t>(
                packet[transport_offset + 12] >> 4) * 4;

        if (tcp_header_length < 20 ||
            tcp_header_length > ip_payload_length ||
            !hasBytes(packet, transport_offset, tcp_header_length)) {
            return result;
        }

        const std::size_t payload_offset =
            transport_offset + tcp_header_length;

        const std::size_t payload_length =
            ip_payload_length - tcp_header_length;

        result.data.assign(
            packet.begin() + payload_offset,
            packet.begin() + payload_offset + payload_length);
    } else {
        // UDP header.
        if (ip_payload_length < 8 ||
            !hasBytes(packet, transport_offset, 8)) {
            return result;
        }

        const std::size_t udp_length =
            read16(packet, transport_offset + 4);

        if (udp_length < 8 || udp_length > ip_payload_length) {
            return result;
        }

        const std::size_t payload_offset =
            transport_offset + 8;

        const std::size_t payload_length = udp_length - 8;

        result.data.assign(
            packet.begin() + payload_offset,
            packet.begin() + payload_offset + payload_length);
    }

    result.valid = true;
    return result;
}

} // namespace DataPackets
