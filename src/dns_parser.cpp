
#include "dns_parser.hpp"

namespace DataPackets {

namespace {

std::uint16_t read16(
    const std::vector<std::uint8_t>& data,
    std::size_t offset
) {
    return (static_cast<std::uint16_t>(data[offset]) << 8) |
           static_cast<std::uint16_t>(data[offset + 1]);
}

bool decodeName(
    const std::vector<std::uint8_t>& data,
    std::size_t& offset,
    std::string& domain
) {
    std::size_t pos = offset;
    std::size_t next_offset = offset;
    bool jumped = false;
    std::size_t jumps = 0;

    domain.clear();

    while (pos < data.size()) {
        std::uint8_t length = data[pos];

        // End of a DNS name.
        if (length == 0) {
            if (!jumped) {
                next_offset = pos + 1;
            }

            offset = next_offset;
            return true;
        }

        // DNS compression pointer.
        if ((length & 0xC0) == 0xC0) {
            if (pos + 1 >= data.size() || ++jumps > 32) {
                return false;
            }

            std::size_t pointer =
                (static_cast<std::size_t>(length & 0x3F) << 8) |
                data[pos + 1];

            if (pointer >= data.size()) {
                return false;
            }

            if (!jumped) {
                next_offset = pos + 2;
                jumped = true;
            }

            pos = pointer;
            continue;
        }

        // Reserved label encodings are not supported.
        if ((length & 0xC0) != 0 || length > 63 ||
            pos + 1 + length > data.size()) {
            return false;
        }

        if (!domain.empty()) {
            domain += '.';
        }

        for (std::size_t i = 0; i < length; ++i) {
            char c = static_cast<char>(data[pos + 1 + i]);

            // Avoid displaying control characters as domain text.
            if (c < 0x21 || c > 0x7E) {
                return false;
            }

            domain += c;
        }

        pos += 1 + length;

        if (!jumped) {
            next_offset = pos;
        }
    }

    return false;
}

}

DNSQuery DNSParser::parse(
    const std::vector<std::uint8_t>& payload
) {
    DNSQuery result;

    // DNS header is 12 bytes.
    if (payload.size() < 12) {
        return result;
    }

    std::uint16_t flags = read16(payload, 2);
    std::uint16_t question_count = read16(payload, 4);

    result.is_response = (flags & 0x8000) != 0;

    // This parser extracts the first question name only.
    if (question_count == 0) {
        return result;
    }

    std::size_t offset = 12;

    if (!decodeName(payload, offset, result.domain)) {
        result.domain.clear();
        return result;
    }

    // QTYPE and QCLASS follow the encoded domain name.
    if (offset + 4 > payload.size()) {
        result.domain.clear();
        return result;
    }

    result.query_type = read16(payload, offset);

    result.valid = !result.domain.empty();
    return result;
}

}
