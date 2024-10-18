#include "SimbaDecoder.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <cstdint>
#include <arpa/inet.h>
#include <variant>

// Структуры для заголовков PCAP файла
struct PCAPFileHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PCAPPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

// Структуры для заголовков сетевых протоколов
struct EthernetHeader {
    uint8_t destMac[6];
    uint8_t srcMac[6];
    uint16_t etherType;  // Изменено с ether_type на etherType
};

struct IPHeader {
    uint8_t versionIHL;  // Изменено с ver_ihl на versionIHL
    uint8_t typeOfService;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsFragmentOffset;
    uint8_t timeToLive;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint32_t srcIP;
    uint32_t destIP;  // Изменено с dst_addr на destIP
};

struct UDPHeader {
    uint16_t srcPort;
    uint16_t destPort;  // Изменено с dst_port на destPort
    uint16_t length;
    uint16_t checksum;
};

const uint16_t SIMBA_PORT = 44040; // Замените на актуальный порт
const uint32_t SIMBA_MULTICAST_IP = 0xEFC31452; // 239.195.20.82 в сетевом порядке байт

class PCAPParser {
public:
    PCAPParser(const std::string& filename) : file(filename, std::ios::binary) {
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + filename);
        }
        std::cout << "File opened successfully: " << filename << std::endl;
        
        // Get file size
        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        std::cout << "File size: " << fileSize << " bytes" << std::endl;

        readFileHeader();
    }

void parsePackets(SimbaDecoder& decoder) {
    PCAPPacketHeader packetHeader;
    std::vector<uint8_t> packetData;
    int packetCount = 0;

    while (file.read(reinterpret_cast<char*>(&packetHeader), sizeof(PCAPPacketHeader))) {
        packetHeader.ts_sec = le32toh(packetHeader.ts_sec);
        packetHeader.ts_usec = le32toh(packetHeader.ts_usec);
        packetHeader.incl_len = le32toh(packetHeader.incl_len);
        packetHeader.orig_len = le32toh(packetHeader.orig_len);

        packetData.resize(packetHeader.incl_len);
        if (!file.read(reinterpret_cast<char*>(packetData.data()), packetHeader.incl_len)) {
            throw std::runtime_error("Failed to read packet data");
        }

        //std::cout << "Packet " << ++packetCount << ":" << std::endl;
        //std::cout << "  Timestamp: " << packetHeader.ts_sec << "." << packetHeader.ts_usec << std::endl;
        //std::cout << "  Captured Length: " << packetHeader.incl_len << std::endl;
        //std::cout << "  Actual Length: " << packetHeader.orig_len << std::endl;

        // Parse Ethernet header
        if (packetData.size() < sizeof(EthernetHeader)) {
            //std::cout << "  Packet too short for Ethernet header" << std::endl;
            continue;
        }
        const EthernetHeader* ethHeader = reinterpret_cast<const EthernetHeader*>(packetData.data());
        uint16_t etherType = ntohs(ethHeader->etherType);
        //std::cout << "  Ether Type: 0x" << std::hex << etherType << std::dec << std::endl;

        // Parse IP header
        if (etherType != 0x0800 || packetData.size() < sizeof(EthernetHeader) + sizeof(IPHeader)) {
            //std::cout << "  Not an IPv4 packet or too short for IP header" << std::endl;
            continue;
        }
        const IPHeader* ipHeader = reinterpret_cast<const IPHeader*>(packetData.data() + sizeof(EthernetHeader));
        uint8_t ipHeaderLength = (ipHeader->versionIHL & 0x0F) * 4;
        char srcIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ipHeader->srcIP, srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ipHeader->destIP, destIP, INET_ADDRSTRLEN);
        //std::cout << "  IP: " << srcIP << " -> " << destIP << std::endl;
        //std::cout << "  Protocol: " << static_cast<int>(ipHeader->protocol) << std::endl;

        // Parse UDP header
        if (ipHeader->protocol != 17 || packetData.size() < sizeof(EthernetHeader) + ipHeaderLength + sizeof(UDPHeader)) {
            //std::cout << "  Not a UDP packet or too short for UDP header" << std::endl;
            continue;
        }
        const UDPHeader* udpHeader = reinterpret_cast<const UDPHeader*>(packetData.data() + sizeof(EthernetHeader) + ipHeaderLength);
        uint16_t srcPort = ntohs(udpHeader->srcPort);
        uint16_t destPort = ntohs(udpHeader->destPort);
        //std::cout << "  UDP: " << srcPort << " -> " << destPort << std::endl;

        // Calculate offset to SIMBA data
        size_t simbaOffset = sizeof(EthernetHeader) + ipHeaderLength + sizeof(UDPHeader);
        size_t simbaLength = packetData.size() - simbaOffset;

        //std::cout << "  SIMBA data offset: " << simbaOffset << std::endl;
        //std::cout << "  SIMBA data length: " << simbaLength << std::endl;

        // Print first few bytes of the SIMBA data
        //std::cout << "  First 32 bytes of SIMBA data: ";
        //for (size_t i = 0; i < std::min(size_t(32), simbaLength); ++i) {
        //    std::cout << std::hex << std::setw(2) << std::setfill('0') 
        //              << static_cast<int>(packetData[simbaOffset + i]) << " ";
        //}
        //std::cout << std::dec << std::endl;

        // Try to decode SIMBA message
        auto result = decoder.decodeMessage(packetData.data() + simbaOffset, simbaLength);
        if (result) {
            std::visit([](auto&& msg) {
                using T = std::decay_t<decltype(msg)>;
                if constexpr (std::is_same_v<T, OrderUpdate>) {
                    //std::cout << "  Received OrderUpdate" << std::endl;
                } else if constexpr (std::is_same_v<T, OrderExecution>) {
                    //std::cout << "  Received OrderExecution" << std::endl;
                } else if constexpr (std::is_same_v<T, OrderBookSnapshot>) {
                    //std::cout << "  Received OrderBookSnapshot" << std::endl;
                }
            }, *result);
        } else {
            //std::cout << "  Failed to decode message" << std::endl;
        }

        //std::cout << std::endl;

        //if (packetCount >= 10) break;  // Limit to first 10 packets for now
    }
}    

private:
    std::ifstream file;
    PCAPFileHeader fileHeader;

void readFileHeader() {
    //std::cout << "Attempting to read PCAP file header..." << std::endl;
    
    // Read first 24 bytes directly
    char buffer[24];
    file.read(buffer, 24);
    if (file.gcount() != 24) {
        throw std::runtime_error("Failed to read first 24 bytes. Bytes read: " + std::to_string(file.gcount()));
    }

    //std::cout << "First 24 bytes: ";
    //for (int i = 0; i < 24; ++i) {
    //    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(buffer[i])) << " ";
    //}
    //std::cout << std::dec << std::endl;

    // Reset file position
    file.seekg(0, std::ios::beg);

    // Now try to read the full header
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(PCAPFileHeader));
    if (file.gcount() != sizeof(PCAPFileHeader)) {
        throw std::runtime_error("Failed to read PCAP file header. Bytes read: " + std::to_string(file.gcount()));
    }

    //std::cout << "Magic number: 0x" << std::hex << fileHeader.magic_number << std::dec << std::endl;

    // Try both little-endian and big-endian interpretations
    PCAPFileHeader leHeader = fileHeader;
    PCAPFileHeader beHeader = fileHeader;

    // Convert big-endian to host byte order
    beHeader.magic_number = __builtin_bswap32(beHeader.magic_number);
    beHeader.version_major = __builtin_bswap16(beHeader.version_major);
    beHeader.version_minor = __builtin_bswap16(beHeader.version_minor);
    beHeader.thiszone = __builtin_bswap32(beHeader.thiszone);
    beHeader.sigfigs = __builtin_bswap32(beHeader.sigfigs);
    beHeader.snaplen = __builtin_bswap32(beHeader.snaplen);
    beHeader.network = __builtin_bswap32(beHeader.network);

    //std::cout << "Little-endian interpretation:" << std::endl;
    //std::cout << "Magic number: 0x" << std::hex << leHeader.magic_number << std::dec << std::endl;
    //std::cout << "Version: " << leHeader.version_major << "." << leHeader.version_minor << std::endl;
    //std::cout << "Timezone offset: " << leHeader.thiszone << std::endl;
    //std::cout << "Timestamp accuracy: " << leHeader.sigfigs << std::endl;
    //std::cout << "Snapshot length: " << leHeader.snaplen << std::endl;
    //std::cout << "Network type: " << leHeader.network << std::endl;

    //std::cout << "\nBig-endian interpretation:" << std::endl;
    //std::cout << "Magic number: 0x" << std::hex << beHeader.magic_number << std::dec << std::endl;
    //std::cout << "Version: " << beHeader.version_major << "." << beHeader.version_minor << std::endl;
    //std::cout << "Timezone offset: " << beHeader.thiszone << std::endl;
    //std::cout << "Timestamp accuracy: " << beHeader.sigfigs << std::endl;
    //std::cout << "Snapshot length: " << beHeader.snaplen << std::endl;
    //std::cout << "Network type: " << beHeader.network << std::endl;

    // Choose the interpretation that looks more correct
    if (beHeader.magic_number == 0xa1b2c3d4 || beHeader.magic_number == 0xa1b23c4d) {
        fileHeader = beHeader;
        //std::cout << "\nUsing big-endian interpretation" << std::endl;
    } else if (leHeader.magic_number == 0xa1b2c3d4 || leHeader.magic_number == 0xa1b23c4d) {
        fileHeader = leHeader;
        //std::cout << "\nUsing little-endian interpretation" << std::endl;
    } else {
        throw std::runtime_error("Invalid PCAP file format. Unrecognized magic number.");
    }

    //std::cout << "PCAP file header read successfully" << std::endl;
}    

void processPacket(const std::vector<unsigned char>& packet_data, SimbaDecoder& decoder) {
    if (packet_data.size() < sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader)) {
        return; // Пакет слишком короткий
    }

    const EthernetHeader* ethHeader = reinterpret_cast<const EthernetHeader*>(packet_data.data());
    if (ntohs(ethHeader->etherType) != 0x0800) {
        return; // Не IP пакет
    }

    const IPHeader* ipHeader = reinterpret_cast<const IPHeader*>(packet_data.data() + sizeof(EthernetHeader));
    if (ipHeader->protocol != 17) {
        return; // Не UDP пакет
    }

    const UDPHeader* udpHeader = reinterpret_cast<const UDPHeader*>(packet_data.data() + sizeof(EthernetHeader) + (ipHeader->versionIHL & 0x0F) * 4);
    if (ntohs(udpHeader->destPort) != SIMBA_PORT || ntohl(ipHeader->destIP) != SIMBA_MULTICAST_IP) {
        return; // Не SIMBA SPECTRA пакет
    }

    // Получаем указатель на начало данных SIMBA SPECTRA
    const uint8_t* simba_data = packet_data.data() + sizeof(EthernetHeader) + (ipHeader->versionIHL & 0x0F) * 4 + sizeof(UDPHeader);

    // Получаем длину данных SIMBA SPECTRA
    size_t simba_data_length = ntohs(udpHeader->length) - sizeof(UDPHeader);

    // Вывод отладочной информации
    //std::cout << "Packet details:" << std::endl;
    //std::cout << "  Ether Type: 0x" << std::hex << ntohs(ethHeader->etherType) << std::dec << std::endl;
    //std::cout << "  IP Protocol: " << static_cast<int>(ipHeader->protocol) << std::endl;
    //std::cout << "  Source IP: " << (ntohl(ipHeader->srcIP) >> 24) << "." << ((ntohl(ipHeader->srcIP) >> 16) & 0xFF) << "."
    //          << ((ntohl(ipHeader->srcIP) >> 8) & 0xFF) << "." << (ntohl(ipHeader->srcIP) & 0xFF) << std::endl;
    //std::cout << "  Dest IP: " << (ntohl(ipHeader->destIP) >> 24) << "." << ((ntohl(ipHeader->destIP) >> 16) & 0xFF) << "."
    //          << ((ntohl(ipHeader->destIP) >> 8) & 0xFF) << "." << (ntohl(ipHeader->destIP) & 0xFF) << std::endl;
    //std::cout << "  Source Port: " << ntohs(udpHeader->srcPort) << std::endl;
    //std::cout << "  Dest Port: " << ntohs(udpHeader->destPort) << std::endl;
    //std::cout << "  SIMBA data length: " << simba_data_length << std::endl;

    // Декодируем сообщение SIMBA SPECTRA
    auto decoded_message = decoder.decodeMessage(simba_data, simba_data_length);

    // Здесь вы можете обработать декодированное сообщение
    if (decoded_message) {
        std::visit([](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, OrderUpdate>) {
                std::cout << "Received OrderUpdate" << std::endl;
            } else if constexpr (std::is_same_v<T, OrderExecution>) {
                std::cout << "Received OrderExecution" << std::endl;
            } else if constexpr (std::is_same_v<T, OrderBookSnapshot>) {
                std::cout << "Received OrderBookSnapshot" << std::endl;
            }
        }, *decoded_message);
    } else {
        //std::cout << "Failed to decode message" << std::endl;
    }
}

};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    try {
        PCAPParser parser(argv[1]);
        SimbaDecoder decoder;
        parser.parsePackets(decoder);
	decoder.printStatistics();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
