
#ifndef DATAPACKETS_PCAP_READER_HPP
#define DATAPACKETS_PCAP_READER_HPP

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace DataPackets {

struct Packet {
    uint32_t timestamp_seconds = 0;
    uint32_t timestamp_microseconds = 0;
    std::vector<uint8_t> data;
};

class PcapReader {
public:
    bool open(const std::string& filename);
    bool readNextPacket(Packet& packet);
    void close();

    uint32_t getLinkType() const;
    std::string getError() const;

private:
    std::ifstream file;
    uint32_t link_type = 0;
    std::string error_message;
    bool little_endian = true;
    bool nanosecond_precision = false;
};

}

#endif
