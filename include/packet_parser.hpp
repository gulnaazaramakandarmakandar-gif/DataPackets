
#ifndef DATAPACKETS_PACKET_PARSER_HPP
#define DATAPACKETS_PACKET_PARSER_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace DataPackets {

struct PacketInfo {
    bool is_ipv4 = false;

    std::string source_ip;
    std::string destination_ip;
    std::string protocol = "Other";

    std::uint8_t protocol_number = 0;

    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    bool has_ports = false;

    // TCP flags
    bool tcp_syn = false;
    bool tcp_ack = false;
    bool tcp_fin = false;
    bool tcp_rst = false;
};

class PacketParser {
public:
    static PacketInfo parse(
        const std::vector<std::uint8_t>& packet,
        std::uint32_t link_type
    );
};

} // namespace DataPackets

#endif