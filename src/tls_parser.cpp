
#include "tls_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

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
        data[offset + 1]
    );
}

std::uint32_t read24(
    const std::vector<std::uint8_t>& data,
    std::size_t offset)
{
    return (static_cast<std::uint32_t>(data[offset]) << 16) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
            static_cast<std::uint32_t>(data[offset + 2]);
}

} // namespace

std::string extractTlsServerName(
    const std::vector<std::uint8_t>& payload)
{
    // A TLS record header requires five bytes.
    if (!hasBytes(payload, 0, 5)) {
        return {};
    }

    // TLS handshake record.
    if (payload[0] != 0x16) {
        return {};
    }

    // Check for a plausible TLS record version.
    if (payload[1] != 0x03 || payload[2] > 0x04) {
        return {};
    }

    const std::size_t record_length = read16(payload, 3);

    if (record_length < 4 ||
        !hasBytes(payload, 5, record_length)) {
        return {};
    }

    const std::size_t record_end = 5 + record_length;
    std::size_t pos = 5;

    // This implementation examines a ClientHello beginning
    // in this TLS record. It does not reassemble TCP streams.
    if (payload[pos] != 0x01) {
        return {};
    }

    if (!hasBytes(payload, pos, 4)) {
        return {};
    }

    const std::size_t handshake_length = read24(payload, pos + 1);
    pos += 4;

    if (handshake_length > record_end - pos) {
        return {};
    }

    const std::size_t handshake_end = pos + handshake_length;

    // ClientHello: legacy version (2) + random (32).
    if (handshake_length < 34 ||
        !hasBytes(payload, pos, 34)) {
        return {};
    }

    pos += 34;

    // Session ID.
    if (!hasBytes(payload, pos, 1)) {
        return {};
    }

    const std::size_t session_length = payload[pos++];

    if (!hasBytes(payload, pos, session_length)) {
        return {};
    }

    pos += session_length;

    // Cipher suites.
    if (!hasBytes(payload, pos, 2)) {
        return {};
    }

    const std::size_t cipher_length = read16(payload, pos);
    pos += 2;

    if (!hasBytes(payload, pos, cipher_length)) {
        return {};
    }

    pos += cipher_length;

    // Compression methods.
    if (!hasBytes(payload, pos, 1)) {
        return {};
    }

    const std::size_t compression_length = payload[pos++];

    if (!hasBytes(payload, pos, compression_length)) {
        return {};
    }

    pos += compression_length;

    // Extensions are optional in older ClientHello messages.
    if (pos == handshake_end) {
        return {};
    }

    if (!hasBytes(payload, pos, 2)) {
        return {};
    }

    const std::size_t extensions_length = read16(payload, pos);
    pos += 2;

    if (extensions_length > handshake_end - pos) {
        return {};
    }

    const std::size_t extensions_end = pos + extensions_length;

    while (pos < extensions_end) {
        if (!hasBytes(payload, pos, 4) ||
            pos + 4 > extensions_end) {
            return {};
        }

        const std::uint16_t extension_type = read16(payload, pos);
        const std::size_t extension_length = read16(payload, pos + 2);
        pos += 4;

        if (extension_length > extensions_end - pos) {
            return {};
        }

        const std::size_t extension_end = pos + extension_length;

        // Server Name Indication extension: type 0.
        if (extension_type == 0x0000) {
            if (!hasBytes(payload, pos, 2) ||
                pos + 2 > extension_end) {
                return {};
            }

            const std::size_t list_length = read16(payload, pos);
            pos += 2;

            if (list_length > extension_end - pos) {
                return {};
            }

            const std::size_t list_end = pos + list_length;

            while (pos < list_end) {
                if (!hasBytes(payload, pos, 3) ||
                    pos + 3 > list_end) {
                    return {};
                }

                const std::uint8_t name_type = payload[pos++];
                const std::size_t name_length = read16(payload, pos);
                pos += 2;

                if (name_length > list_end - pos) {
                    return {};
                }

                if (name_type == 0 && name_length > 0) {
                    std::string hostname;
                    hostname.reserve(name_length);

                    for (std::size_t i = 0; i < name_length; ++i) {
                        const unsigned char ch = payload[pos + i];

                        // Hostnames are expected to be ASCII-compatible.
                        if (ch < 0x21 || ch > 0x7e) {
                            return {};
                        }

                        hostname.push_back(static_cast<char>(ch));
                    }

                    return hostname;
                }

                pos += name_length;
            }

            return {};
        }

        pos = extension_end;
    }

    return {};
}

} // namespace DataPackets
