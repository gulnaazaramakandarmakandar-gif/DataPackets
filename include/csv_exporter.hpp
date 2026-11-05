#ifndef DATAPACKETS_CSV_EXPORTER_HPP
#define DATAPACKETS_CSV_EXPORTER_HPP

#include <fstream>
#include <string>
#include <vector>

namespace DataPackets {

class CsvExporter {
public:
    explicit CsvExporter(const std::string& filename);
    bool isOpen() const;
    void writeRow(const std::vector<std::string>& values);

private:
    std::ofstream file;
    static std::string escapeField(const std::string& value);
};

} // namespace DataPackets

#endif // DATAPACKETS_CSV_EXPORTER_HPP
