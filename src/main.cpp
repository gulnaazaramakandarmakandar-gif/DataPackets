#include <algorithm>

#include <cstdint>

#include <iostream>

#include <map>

#include <set>

#include <string>

#include <tuple>

#include <utility>

#include <vector>

#include "pcap_reader.hpp"

#include "packet_parser.hpp"

#include "flow_tracker.hpp"

#include "filter.hpp"

#include "dns_parser.hpp"

#include "transport_parser.hpp"
#include "csv_exporter.hpp"
#include "tls_parser.hpp"

int main(int argc, char* argv[])

{

    if (argc < 2)

    {

        std::cerr

            << "Usage: datapackets.exe <pcap_file> "

            << "[--protocol TCP|UDP] "

            << "[--ip ADDRESS] "

            << "[--port PORT] "
                << "[--csv OUTPUT.csv]\n";

        return 1;

    }

    const std::string filename = argv[1];

    DataPackets::FilterOptions filter;
    std::string csv_filename;

    // Parse command-line filters.

    for (int i = 2; i < argc; ++i)

    {

        const std::string argument = argv[i];

        if (argument == "--help")

        {

            std::cout

                << "Usage: datapackets.exe <pcap_file> "

                << "[--protocol TCP|UDP] "

                << "[--ip ADDRESS] "

                << "[--port PORT] "
                << "[--csv OUTPUT.csv]\n";

            return 0;

        }

        else if (argument == "--protocol" && i + 1 < argc)

        {

            filter.protocol = argv[++i];

        }

        else if (argument == "--ip" && i + 1 < argc)

        {

            filter.ip = argv[++i];

        }

        else if (argument == "--port" && i + 1 < argc)

        {

            try

            {

                filter.port = std::stoi(argv[++i]);

            }

            catch (...)

            {

                std::cerr << "Error: Invalid port number.\n";

                return 1;

            }

            if (filter.port < 0 || filter.port > 65535)

            {

                std::cerr

                    << "Error: Port must be between 0 and 65535.\n";

                return 1;

            }

        }
        else if (argument == "--csv" && i + 1 < argc) {
            csv_filename = argv[++i];
        }

        else

        {

            std::cerr << "Unknown or incomplete argument: "

                      << argument << '\n';

            return 1;

        }

    }

    // Open PCAP file.

    DataPackets::PcapReader reader;

    if (!reader.open(filename))

    {

        std::cerr << "Error: Could not open PCAP file: "

                  << filename << '\n'

                  << reader.getError() << '\n';

        return 1;

    }

    const std::uint32_t link_type = reader.getLinkType();

    // Packet statistics.

    std::uint64_t packets_matched = 0;

    std::uint64_t ipv4_packets_matched = 0;

    std::uint64_t captured_bytes_matched = 0;

    std::map<std::string, std::uint64_t> protocol_counts;

    // Port-based traffic statistics.

    struct PortStats

    {

        std::uint64_t packets = 0;

        std::uint64_t bytes = 0;

    };

    using PortKey = std::pair<std::string, std::uint16_t>;

    std::map<PortKey, PortStats> port_stats;

    // Per-IP traffic statistics.
    struct IPStats
    {
        std::uint64_t packets_sent = 0;
        std::uint64_t bytes_sent = 0;
        std::uint64_t packets_received = 0;
        std::uint64_t bytes_received = 0;
    };

    std::map<std::string, IPStats> ip_stats;

    // TCP statistics.

    std::uint64_t tcp_syn_count = 0;

    std::uint64_t tcp_ack_count = 0;

    std::uint64_t tcp_fin_count = 0;

    std::uint64_t tcp_rst_count = 0;

    std::uint64_t tcp_connection_attempts = 0;

    using Endpoint = std::pair<std::string, std::uint16_t>;

    using ConnectionKey = std::tuple<Endpoint, Endpoint>;

    std::set<ConnectionKey> initial_syns;

    std::set<ConnectionKey> syn_acks;

    std::set<ConnectionKey> completed_handshakes;

    std::set<ConnectionKey> reset_connections;

    // DNS statistics.

    std::uint64_t dns_messages = 0;

    std::uint64_t dns_queries = 0;

    std::uint64_t dns_responses = 0;

    std::set<std::string> unique_domains;

    // TLS Server Name Indication (SNI) observations.
    std::uint64_t tls_payloads_inspected = 0;
    std::set<std::string> tls_server_names;

    // Flow tracking.

    DataPackets::FlowTracker flow_tracker;

    DataPackets::Packet captured_packet;

    while (reader.readNextPacket(captured_packet))

    {

        const auto& packet = captured_packet.data;

        const DataPackets::PacketInfo info =

            DataPackets::PacketParser::parse(packet, link_type);

        if (!DataPackets::matchesFilter(info, filter))

        {

            continue;

        }

        ++packets_matched;

        captured_bytes_matched += packet.size();

        if (info.is_ipv4)

        {

            ++ipv4_packets_matched;

        }

        ++protocol_counts[info.protocol];

    // Track traffic sent and received by each IPv4 address.
    if (info.is_ipv4 &&
        !info.source_ip.empty() &&
        !info.destination_ip.empty())
    {
        auto& source_stats = ip_stats[info.source_ip];
        ++source_stats.packets_sent;
        source_stats.bytes_sent += packet.size();

        auto& destination_stats = ip_stats[info.destination_ip];
        ++destination_stats.packets_received;
        destination_stats.bytes_received += packet.size();
    }

        // Attribute each packet to both endpoint ports so server responses

        // and client requests are both represented in the port report.

        // A packet may therefore contribute to two port entries.

        if (info.has_ports &&

            (info.protocol == "TCP" || info.protocol == "UDP"))

        {

            auto& source_stats = port_stats[{info.protocol, info.source_port}];

            ++source_stats.packets;

            source_stats.bytes += packet.size();

            auto& destination_stats =

                port_stats[{info.protocol, info.destination_port}];

            ++destination_stats.packets;

            destination_stats.bytes += packet.size();

        }

        // TCP flag analysis and approximate handshake tracking.

        if (info.protocol == "TCP" && info.has_ports)

        {

            const Endpoint source = {

                info.source_ip, info.source_port

            };

            const Endpoint destination = {

                info.destination_ip, info.destination_port

            };

            if (info.tcp_syn)

            {

                ++tcp_syn_count;

                if (!info.tcp_ack)

                {

                    ++tcp_connection_attempts;

                    initial_syns.emplace(source, destination);

                }

                else

                {

                    // Store SYN-ACK using the initial SYN direction.

                    syn_acks.emplace(destination, source);

                }

            }

            if (info.tcp_ack)

            {

                ++tcp_ack_count;

                // A SYN-ACK is not the final handshake ACK.

                if (!info.tcp_syn)

                {

                    const ConnectionKey key = {

                        source,destination

                    };

                    if (syn_acks.count(key) > 0)

                    {

                        completed_handshakes.insert(key);

                    }

                }

            }

            if (info.tcp_fin)

            {

                ++tcp_fin_count;

            }

            if (info.tcp_rst)

            {

                ++tcp_rst_count;

                if (source < destination)

                {

                    reset_connections.emplace(source, destination);

                }

                else

                {

                    reset_connections.emplace(destination, source);

                }

            }

        }

        // Track bidirectional flows.

        flow_tracker.addPacket(info, packet.size());

        // Inspect TCP payloads for a TLS ClientHello SNI hostname.
        if (info.protocol == "TCP" && info.has_ports)
        {
            const DataPackets::TransportPayload tls_payload =
                DataPackets::extractTransportPayload(packet, link_type);

            if (tls_payload.valid && !tls_payload.data.empty())
            {
                ++tls_payloads_inspected;
                const std::string server_name =
                    DataPackets::extractTlsServerName(tls_payload.data);
                if (!server_name.empty())
                {
                    tls_server_names.insert(server_name);
                }
            }
        }

        // Parse DNS over UDP port 53.

        if (info.protocol == "UDP" && info.has_ports &&

            (info.source_port == 53 ||

             info.destination_port == 53))

        {

            const DataPackets::TransportPayload payload =

                DataPackets::extractTransportPayload(packet, link_type);

            if (payload.valid)

            {

                const DataPackets::DNSQuery dns =

                    DataPackets::DNSParser::parse(payload.data);

                if (dns.valid)

                {

                    ++dns_messages;

                    if (dns.is_response)

                    {

                        ++dns_responses;

                    }

                    else

                    {

                        ++dns_queries;

                    }

                    if (!dns.domain.empty())

                    {

                        unique_domains.insert(dns.domain);

                    }

                }

            }

        }

    }

    reader.close();

    // Estimate incomplete handshakes.

    std::uint64_t incomplete_handshakes = 0;

    for (const auto& connection : initial_syns)

    {

        if (syn_acks.count(connection) == 0 ||

            completed_handshakes.count(connection) == 0)

        {

            ++incomplete_handshakes;

        }

    }

    // Main report.

    std::cout

        << "\n========================================\n"

        << "          DataPackets Analyzer\n"

        << "========================================\n";

    std::cout << "Capture file: " << filename << '\n';

    std::cout << "\n========== PACKET STATISTICS ==========\n"

              << "Packets matched: " << packets_matched << '\n'

              << "IPv4 packets matched: " << ipv4_packets_matched << '\n'

              << "Captured bytes matched: "

              << captured_bytes_matched << '\n';

    std::cout << "\n========== PROTOCOL BREAKDOWN ==========\n";

    for (const auto& entry : protocol_counts)

    {

        std::cout << entry.first << ": "

                  << entry.second << '\n';

    }

    // Port report, ordered by attributed bytes (largest first).

    std::vector<std::pair<PortKey, PortStats>> sorted_ports(

        port_stats.begin(), port_stats.end());

    std::sort(sorted_ports.begin(), sorted_ports.end(),

        [](const auto& left, const auto& right)

        {

            if (left.second.bytes != right.second.bytes)

            {

                return left.second.bytes > right.second.bytes;

            }

            return left.second.packets > right.second.packets;

        });

    std::cout << "\n=========== PORT TRAFFIC ANALYSIS =========\n";

    if (sorted_ports.empty())

    {

        std::cout << "No TCP/UDP port traffic was found in the matched packets.\n";

    }

    else

    {

        for (const auto& entry : sorted_ports)

        {

            std::cout << entry.first.first << " port " << entry.first.second

                      << " | Endpoint packet observations: "

                      << entry.second.packets

                      << " | Attributed bytes: " << entry.second.bytes << '\n';

        }

        std::cout << "Most active port: " << sorted_ports.front().first.first

                  << " port " << sorted_ports.front().first.second << '\n';

    }

    std::cout << "Note: Packets are attributed to both source and destination "

              << "ports, so port totals are not unique packet totals.\n";

    // Top Talkers report, sorted by total attributed bytes.
    using IPTalkerEntry = std::pair<std::string, IPStats>;
    std::vector<IPTalkerEntry> sorted_ip_stats(ip_stats.begin(), ip_stats.end());

    std::sort(sorted_ip_stats.begin(), sorted_ip_stats.end(),
        [](const auto& left, const auto& right)
        {
            const std::uint64_t left_bytes =
                left.second.bytes_sent + left.second.bytes_received;
            const std::uint64_t right_bytes =
                right.second.bytes_sent + right.second.bytes_received;

            if (left_bytes != right_bytes)
            {
                return left_bytes > right_bytes;
            }

            return left.second.packets_sent + left.second.packets_received >
                   right.second.packets_sent + right.second.packets_received;
        });

    std::cout << "\n========== TOP TALKERS ANALYSIS ==========\n";

    if (sorted_ip_stats.empty())
    {
        std::cout << "No IPv4 traffic was found in the matched packets.\n";
    }
    else
    {
        for (const auto& entry : sorted_ip_stats)
        {
            const auto& ip = entry.first;
            const auto& stats = entry.second;

            std::cout << ip
                      << " | Sent: " << stats.packets_sent
                      << " packets, " << stats.bytes_sent << " bytes"
                      << " | Received: " << stats.packets_received
                      << " packets, " << stats.bytes_received << " bytes"
                      << " | Total attributed bytes: "
                      << stats.bytes_sent + stats.bytes_received << '\n';
        }

        std::cout << "Top talker by attributed bytes: "
                  << sorted_ip_stats.front().first << '\n';
    }

    std::cout << "Note: Each IPv4 packet contributes to its source IP's sent "
              << "traffic and destination IP's received traffic.\n";

    std::cout << "\n============= TCP ANALYSIS =============\n"

              << "SYN flags: " << tcp_syn_count << '\n'

              << "ACK flags: " << tcp_ack_count << '\n'

              << "FIN flags: " << tcp_fin_count << '\n'

              << "RST flags: " << tcp_rst_count << '\n'

              << "Initial TCP connection attempts: "

              << tcp_connection_attempts << '\n';

    std::cout << "\nTCP handshake outcome estimates:\n"

              << "Completed handshakes observed: "

              << completed_handshakes.size() << '\n'

              << "Reset connections observed: "

              << reset_connections.size() << '\n'

              << "Incomplete handshakes observed: "

              << incomplete_handshakes << '\n'

              << "Note: Partial captures and reused endpoint pairs "

              << "can affect these estimates.\n";

    // DNS report.

    std::cout << "\n============== DNS ANALYSIS ============\n"

              << "DNS messages parsed: " << dns_messages << '\n'

              << "DNS queries: " << dns_queries << '\n'

              << "DNS responses: " << dns_responses << '\n'

              << "Unique domains: " << unique_domains.size() << '\n';

    if (!unique_domains.empty())

    {

        std::cout << "\nUnique domain names:\n";

        for (const auto& domain : unique_domains)

        {

            std::cout << "  " << domain << '\n';

        }

    }

    // TLS SNI report.
    std::cout << "\n============== TLS SNI ANALYSIS ============\n"
              << "Non-empty TCP payloads inspected: "
              << tls_payloads_inspected << '\n'
              << "Unique TLS SNI hostnames: "
              << tls_server_names.size() << '\n';

   if (!tls_server_names.empty())
   {
    std::cout << "Hostnames found:\n";
    for (const auto& hostname : tls_server_names){
        std::cout << "  " << hostname << '\n';
    }

    std::cout << "Hostnames printed: "
              << tls_server_names.size() << '\n';
    }
    else
    {
        std::cout << "No SNI hostname extracted from the inspected TCP payloads.\n"
                  << "Possible reasons: no ClientHello was captured, payload was "
                  << "split across TCP segments, or SNI was unavailable.\n";
    }
    std::cout << "Note: This first version inspects each TCP payload separately; "
              << "TCP stream reassembly is not implemented.\n";

    // Flow report and detection counters.

    const auto& flows = flow_tracker.getFlows();

    std::uint64_t one_way_flows = 0;

    std::uint64_t single_packet_tcp_flows = 0;

    std::cout << "\n============== FLOW ANALYSIS ===========\n"

              << "Unique TCP/UDP endpoint flows: "

              << flows.size() << '\n';

    for (const auto& entry : flows)

    {

        const auto& key = entry.first;

        const auto& stats = entry.second;

        std::cout << key

                  << " | Packets: " << stats.packets

                  << " | Bytes: " << stats.bytes

                  << "\n    A -> B: "

                  << stats.packets_a_to_b << " packets, "

                  << stats.bytes_a_to_b << " bytes"

                  << "\n    B -> A: "

                  << stats.packets_b_to_a << " packets, "

                  << stats.bytes_b_to_a << " bytes\n";

        if (key.find("[TCP]") != std::string::npos)

        {

            std::cout << "    TCP FLOW STATE:\n"

                      << "      SYN observed: "

                      << (stats.syn_seen ? "Yes" : "No") << '\n'

                      << "      SYN-ACK observed: "

                      << (stats.syn_ack_seen ? "Yes" : "No") << '\n'

                      << "      Handshake completion observed: "

                      << (stats.handshake_completed ? "Yes" : "No")

                      << '\n'

                      << "      RST observed: "

                      << (stats.reset_seen ? "Yes" : "No") << '\n'

                      << "      FIN observed: "

                      << (stats.fin_seen ? "Yes" : "No") << '\n';

        }

        if (stats.packets_a_to_b == 0 ||

            stats.packets_b_to_a == 0)

        {

            ++one_way_flows;

        }

        if (key.find("[TCP]") != std::string::npos &&

            stats.packets == 1)

        {

            ++single_packet_tcp_flows;

        }

    }

    std::cout << "\nOne-way flows: " << one_way_flows << '\n';

    std::cout << "\n====== SINGLE-PACKET FLOW ANALYSIS ======\n";

    for (const auto& entry : flows)

    {

        const auto& key = entry.first;

        const auto& stats = entry.second;

        if (key.find("[TCP]") != std::string::npos &&

            stats.packets == 1)

        {

            std::cout << "Review: " << key

                      << " | Packets: " << stats.packets

                      << " | Bytes: " << stats.bytes << '\n';

        }

    }

    std::cout << "Single-packet TCP flows: "

              << single_packet_tcp_flows << '\n'

              << "Note: Single-packet flows are not necessarily "

              << "malicious; the capture may be incomplete.\n";

    // New suspicious traffic review section.

    std::uint64_t one_way_alerts = 0;

    std::uint64_t single_packet_alerts = 0;

    for (const auto& entry : flows)

    {

        const auto& key = entry.first;

        const auto& stats = entry.second;

        if (stats.packets_a_to_b == 0 ||

            stats.packets_b_to_a == 0)

        {

            ++one_way_alerts;

        }

        if (key.find("[TCP]") != std::string::npos &&

            stats.packets == 1)

        {

            ++single_packet_alerts;

        }

    }

    std::cout << "\n====== SUSPICIOUS TRAFFIC ALERTS ======\n";

    std::uint64_t alerts_reported = 0;

    for (const auto& entry : flows)

    {

        const auto& key = entry.first;

        const auto& stats = entry.second;

        const bool is_one_way =

            stats.packets_a_to_b == 0 ||

            stats.packets_b_to_a == 0;

        const bool is_single_packet_tcp =

            key.find("[TCP]") != std::string::npos &&

            stats.packets == 1;

        if (!is_one_way && !is_single_packet_tcp)

        {

            continue;

        }

        ++alerts_reported;

        std::cout << "[REVIEW] " << key << '\n';

        if (is_one_way)

        {

            std::cout

                << "    Reason: Traffic was observed in only one "

                << "direction.\n";

        }
        
        if (is_single_packet_tcp)
        {
            std::cout
                << "    Reason: TCP flow contains only one captured "
                << "packet.\n";
        }

        std::cout
            << "    Assessment: Investigate with capture context; "
            << "this is not proof of malicious activity.\n";
    }

    if (alerts_reported == 0)
    {
        std::cout << "No flows matched the current review rules.\n";
    }

    std::cout << "\nAlert summary:\n"
              << "One-way flows flagged: " << one_way_alerts << '\n'
              << "Single-packet TCP flows flagged: "
              << single_packet_alerts << '\n'
              << "Total flows flagged for review: "
              << alerts_reported << '\n';

    std::cout
        << "\n========================================\n"
        << "Analysis completed successfully.\n";

    // Export analysis results to CSV when --csv is provided.
    if (!csv_filename.empty())
    {
        DataPackets::CsvExporter csv(csv_filename);

        if (!csv.isOpen())
        {
            std::cerr << "Error: Could not write CSV file: "
                      << csv_filename << '\n';
            return 1;
        }

        // Keep every row the same width for spreadsheet compatibility.
        auto writeCsvRow = [&](std::vector<std::string> fields)
        {
            fields.resize(12);
            csv.writeRow(fields);
        };

        writeCsvRow({
    "Section",
    "Item",
    "Protocol",
    "Port",
    "Packets",
    "Bytes",
    "Packets Sent",
    "Bytes Sent",
    "Packets Received",
    "Bytes Received",
    "Status",
    "Details"
});

        // 1. Packet statistics
        writeCsvRow({"Packet Statistics", "Metric", "Count / Value"});

        writeCsvRow({"Packet Statistics", "Packets matched",
             std::to_string(packets_matched)});
        writeCsvRow({"Packet Statistics", "IPv4 packets matched",
             std::to_string(ipv4_packets_matched)});
        writeCsvRow({"Packet Statistics", "Captured bytes matched",
             std::to_string(captured_bytes_matched)});
        // 2. Protocol breakdown
        // 2. Protocol breakdown
        writeCsvRow({"Protocol Breakdown", "Protocol", "Packet Count"});

        for (const auto& entry : protocol_counts){
            writeCsvRow({"Protocol Breakdown", entry.first,
                 std::to_string(entry.second)});
}

        // 3. Port traffic
        // 3. Port traffic
        writeCsvRow({
            "Port Traffic",
            "Protocol",
            "Port",
            "Packet Count",
            "Total Bytes"
    
        });

        for (const auto& entry : sorted_ports){
            writeCsvRow({
                "Port Traffic",
                entry.first.first,
                std::to_string(entry.first.second),
                std::to_string(entry.second.packets),
                std::to_string(entry.second.bytes)
            });
        }
    

        // 4. Top Talkers
        writeCsvRow({
            "Top Talkers",
            "IP Address",
            "Packets Sent",
            "Bytes Sent",
            "Packets Received",
            "Bytes Received",
            "Total Attributed Bytes"
        });
        for (const auto& entry : sorted_ip_stats)
        {
            const auto& ip = entry.first;
            const auto& stats = entry.second;

            writeCsvRow({
                "Top Talkers", ip,
                std::to_string(stats.packets_sent),
                std::to_string(stats.bytes_sent),
                std::to_string(stats.packets_received),
                std::to_string(stats.bytes_received),
                std::to_string(stats.bytes_sent + stats.bytes_received)
            });
        }

        // 5. DNS statistics and unique domains
        writeCsvRow({
            "DNS Domains",
            "DNS Information",
            "Value"
        });
        writeCsvRow({"DNS Domains", "DNS messages",
                     std::to_string(dns_messages)});
        writeCsvRow({"DNS Domains", "DNS queries",
                     std::to_string(dns_queries)});
        writeCsvRow({"DNS Domains", "DNS responses",
                     std::to_string(dns_responses)});

        for (const auto& domain : unique_domains)
        {
            writeCsvRow({"DNS Domains", domain});
        }

        // 6. TLS SNI hostnames
        writeCsvRow({
            "TLS SNI",
            "TLS Information",
            "Value"
        });
        writeCsvRow({"TLS SNI", "Payloads inspected",
                     std::to_string(tls_payloads_inspected)});

        for (const auto& hostname : tls_server_names)
        {
            writeCsvRow({"TLS SNI", hostname});
        }

        // 7. Network flows
        writeCsvRow({
            "Network Flows",
            "Flow",
            "Total Packets",
            "Total Bytes",
            "Packets A to B",
            "Bytes A to B",
            "Packets B to A",
            "Bytes B to A",
            "SYN Seen",
            "SYN-ACK Seen",
            "Handshake Completed",
            "RST Seen"
        });
        for (const auto& entry : flows)
        {
            const auto& key = entry.first;
            const auto& stats = entry.second;

            writeCsvRow({
                "Network Flows", key,
                std::to_string(stats.packets),
                std::to_string(stats.bytes),
                std::to_string(stats.packets_a_to_b),
                std::to_string(stats.bytes_a_to_b),
                std::to_string(stats.packets_b_to_a),
                std::to_string(stats.bytes_b_to_a),
                stats.syn_seen ? "Yes" : "No",
                stats.syn_ack_seen ? "Yes" : "No",
                stats.handshake_completed ? "Yes" : "No",
                stats.reset_seen ? "Yes" : "No"
            });
        }

        // 8. Suspicious traffic review alerts
        writeCsvRow({
            "Review Alert",
            "Flow",
            "One-way",
            "Single-packet TCP",
            "Reason",
            "Recommendation"
        });

        writeCsvRow({"Review Alerts", "One-way flows flagged",
                     std::to_string(one_way_alerts)});
        writeCsvRow({"Review Alerts", "Single-packet TCP flows flagged",
                     std::to_string(single_packet_alerts)});
        writeCsvRow({"Review Alerts", "Total flows flagged",
                     std::to_string(alerts_reported)});

        for (const auto& entry : flows)
        {
            const auto& key = entry.first;
            const auto& stats = entry.second;

            const bool one_way =
                stats.packets_a_to_b == 0 ||
                stats.packets_b_to_a == 0;

            const bool single_packet_tcp =
                key.find("[TCP]") != std::string::npos &&
                stats.packets == 1;

            if (one_way || single_packet_tcp)
            {
                std::string reason;

                if (one_way)
                    reason = "One-way flow";

                if (single_packet_tcp)
                {
                    if (!reason.empty())
                        reason += "; ";

                    reason += "Single-packet TCP flow";
                }

                writeCsvRow({
                    "Review Alert", key,
                    one_way ? "Yes" : "No",
                    single_packet_tcp ? "Yes" : "No",
                    reason,
                    "Investigate with capture context; not proof of malicious activity"
                });
            }
        }

        std::cout << "CSV report written to: "
                  << csv_filename << '\n';
    }

    return 0;
}
