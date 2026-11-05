\# DataPackets – Network Packet Analyzer



\## 📌 Project Overview

DataPackets is a C++ based network packet analyzer that reads PCAP files and analyzes network traffic. It provides protocol statistics, network flow information, DNS analysis, TLS Server Name Indication (SNI) extraction, and review alerts.



\## 🚀 Features

\- PCAP file reading and packet parsing

\- TCP and UDP traffic analysis

\- IP and port filtering

\- TCP flag analysis

\- DNS domain extraction

\- TLS SNI hostname extraction

\- Top Talkers analysis

\- Bidirectional network flow tracking

\- One-way flow detection

\- Single-packet TCP flow detection

\- CSV report generation



\## 🛠️ Technologies Used

\- C++

\- C++17

\- PCAP

\- GCC / MinGW

\- CSV



\## 📂 Project Structure

```text

DataPackets/

├── include/

├── src/

├── datapackets.exe

├── report.csv

└── README.md

```



\## ⚙️ Build Instructions

Compile the project using:



```powershell

g++ -std=c++17 -Wall -Wextra -I include src/main.cpp src/pcap\_reader.cpp src/packet\_parser.cpp src/flow\_tracker.cpp src/filter.cpp src/dns\_parser.cpp src/transport\_parser.cpp src/tls\_parser.cpp src/csv\_exporter.cpp -o datapackets.exe

```



\## ▶️ Usage

Run the analyzer with a PCAP file:



```powershell

.\\datapackets.exe "path\\to\\file.pcap"

```



Generate a CSV report:



```powershell

.\\datapackets.exe "path\\to\\file.pcap" --csv report.csv

```



\## 📊 Output

The analyzer generates:

\- Packet statistics

\- Protocol breakdown

\- Port traffic

\- Top Talkers

\- DNS domains

\- TLS SNI information

\- Network flow summary

\- Review alerts



\## ⚠️ Limitations

\- Review alerts are indicators for further investigation and do not prove malicious activity.

\- TLS SNI extraction examines individual TCP payloads and does not perform TCP stream reassembly.

\- Results depend on the packets available in the supplied PCAP capture.



\## 👩‍💻 Author

Gulnaaz Ara Makandar



\## 📄 License

This project is developed for educational purposes.



