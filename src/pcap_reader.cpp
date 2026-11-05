
#include "pcap_reader.hpp"

#include <array>
#include <limits>

namespace DataPackets {

namespace {

uint32_t decode32(const uint8_t* bytes, bool little_endian) {
    if (little_endian) {
        return static_cast<uint32_t>(bytes[0])
             | (static_cast<uint32_t>(bytes[1]) << 8)
             | (static_cast<uint32_t>(bytes[2]) << 16)
             | (static_cast<uint32_t>(bytes[3]) << 24);
    }

    return (static_cast<uint32_t>(bytes[0]) << 24)
         | (static_cast<uint32_t>(bytes[1]) << 16)
         | (static_cast<uint32_t>(bytes[2]) << 8)
         | static_cast<uint32_t>(bytes[3]);
}

}

bool PcapReader::open(const std::string& filename) {
    close();
    error_message.clear();

    file.open(filename, std::ios::binary);

    if (!file) {
        error_message = "Could not open file: " + filename;
        return false;
    }

    std::array<uint8_t, 24> header{};

    if (!file.read(reinterpret_cast<char*>(header.data()),
                   static_cast<std::streamsize>(header.size()))) {
        error_message = "File is too small to contain a PCAP header.";
        close();
        return false;
    }

    // Detect classic PCAP byte order and timestamp precision.
    if (header[0] == 0xd4 && header[1] == 0xc3 &&
        header[2] == 0xb2 && header[3] == 0xa1) {
        little_endian = true;
        nanosecond_precision = false;
    } else if (header[0] == 0xa1 && header[1] == 0xb2 &&
               header[2] == 0xc3 && header[3] == 0xd4) {
        little_endian = false;
        nanosecond_precision = false;
    } else if (header[0] == 0x4d && header[1] == 0x3c &&
               header[2] == 0xb2 && header[3] == 0xa1) {
        little_endian = true;
        nanosecond_precision = true;
    } else if (header[0] == 0xa1 && header[1] == 0xb2 &&
               header[2] == 0x3c && header[3] == 0x4d) {
        little_endian = false;
        nanosecond_precision = true;
    } else {
        error_message = "Unsupported or invalid PCAP file format.";
        close();
        return false;
    }

    const uint32_t major = decode32(
        (little_endian ? header.data() + 4 : header.data() + 4),
        little_endian
    ) & 0xffff;

    const uint32_t minor = decode32(header.data() + 4, little_endian) >> 16;

    // Version fields are stored as two 16-bit values.
    const uint16_t version_major = little_endian
        ? static_cast<uint16_t>(header[5] << 8 | header[4])
        : static_cast<uint16_t>(header[4] << 8 | header[5]);

    const uint16_t version_minor = little_endian
        ? static_cast<uint16_t>(header[7] << 8 | header[6])
        : static_cast<uint16_t>(header[6] << 8 | header[7]);

    (void)major;
    (void)minor;

    if (version_major != 2 || version_minor != 4) {
        error_message = "Unsupported PCAP version; expected version 2.4.";
        close();
        return false;
    }

    const uint32_t snapshot_length =
        decode32(header.data() + 16, little_endian);

    if (snapshot_length == 0 || snapshot_length > 64 * 1024 * 1024) {
        error_message = "Invalid PCAP snapshot length.";
        close();
        return false;
    }

    link_type = decode32(header.data() + 20, little_endian);

    return true;
}

bool PcapReader::readNextPacket(Packet& packet) {
    if (!file.is_open()) {
        error_message = "No PCAP file is open.";
        return false;
    }

    std::array<uint8_t, 16> packet_header{};

    file.read(reinterpret_cast<char*>(packet_header.data()),
              static_cast<std::streamsize>(packet_header.size()));

    if (file.gcount() == 0 && file.eof()) {
        return false;
    }

    if (file.gcount() != static_cast<std::streamsize>(packet_header.size())) {
        error_message = "Incomplete packet header.";
        return false;
    }

    const uint32_t seconds =
        decode32(packet_header.data(), little_endian);

    const uint32_t fraction =
        decode32(packet_header.data() + 4, little_endian);

    const uint32_t captured_length =
        decode32(packet_header.data() + 8, little_endian);

    const uint32_t original_length =
        decode32(packet_header.data() + 12, little_endian);

    constexpr uint32_t MAX_PACKET_SIZE = 16 * 1024 * 1024;

    if (captured_length > MAX_PACKET_SIZE ||
        original_length < captured_length) {
        error_message = "Invalid packet length in PCAP file.";
        return false;
    }

    if (!nanosecond_precision && fraction >= 1000000) {
        error_message = "Invalid microsecond timestamp.";
        return false;
    }

    if (nanosecond_precision && fraction >= 1000000000) {
        error_message = "Invalid nanosecond timestamp.";
        return false;
    }

    packet.timestamp_seconds = seconds;
    packet.timestamp_microseconds = nanosecond_precision
        ? fraction / 1000
        : fraction;

    packet.data.resize(captured_length);

    if (captured_length > 0 &&
        !file.read(reinterpret_cast<char*>(packet.data.data()),
                   static_cast<std::streamsize>(captured_length))) {
        error_message = "Incomplete packet data.";
        packet.data.clear();
        return false;
    }

    return true;
}

void PcapReader::close() {
    if (file.is_open()) {
        file.close();
    }

    link_type = 0;
}

uint32_t PcapReader::getLinkType() const {
    return link_type;
}

std::string PcapReader::getError() const {
    return error_message;
}

}
