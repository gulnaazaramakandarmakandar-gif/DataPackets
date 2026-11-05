#include "csv_exporter.hpp"

namespace DataPackets {

CsvExporter::CsvExporter(const std::string& filename)
    : file(filename, std::ios::out | std::ios::trunc)
{
}

bool CsvExporter::isOpen() const
{
    return file.is_open();
}

std::string CsvExporter::escapeField(const std::string& value)
{
    std::string escaped = "\"";

    for (char ch : value) {
        if (ch == '"') {
            escaped += "\"\"";
        } else {
            escaped += ch;
        }
    }

    escaped += '"';
    return escaped;
}

void CsvExporter::writeRow(const std::vector<std::string>& values)
{
    if (!file.is_open()) {
        return;
    }

    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            file << ',';
        }
        file << escapeField(values[i]);
    }

    file << '\n';
}

} // namespace DataPackets
