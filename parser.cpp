#include "SimbaDecoder.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <cstdint>
#include <arpa/inet.h>
#include <variant>

#include "log.h"

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
        LOG_INFO("File opened successfully: " << filename);
        
        // Get file size
        file.seekg(0, std::ios::end);
        std::streampos fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        LOG_INFO("File size: " << fileSize << " bytes");

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

        LOG_DEBUG("Packet " << ++packetCount << ":");
        LOG_DEBUG("  Timestamp: " << packetHeader.ts_sec << "." << packetHeader.ts_usec);
        LOG_DEBUG("  Captured Length: " << packetHeader.incl_len);
        LOG_DEBUG("  Actual Length: " << packetHeader.orig_len);

        // Parse Ethernet header
        if (packetData.size() < sizeof(EthernetHeader)) {
            LOG_DEBUG("  Packet too short for Ethernet header");
            continue;
        }
        const EthernetHeader* ethHeader = reinterpret_cast<const EthernetHeader*>(packetData.data());
        uint16_t etherType = ntohs(ethHeader->etherType);
        LOG_DEBUG("  Ether Type: 0x" << std::hex << etherType << std::dec);

        // Parse IP header
        if (etherType != 0x0800 || packetData.size() < sizeof(EthernetHeader) + sizeof(IPHeader)) {
            LOG_DEBUG("  Not an IPv4 packet or too short for IP header");
            continue;
        }
        const IPHeader* ipHeader = reinterpret_cast<const IPHeader*>(packetData.data() + sizeof(EthernetHeader));
        uint8_t ipHeaderLength = (ipHeader->versionIHL & 0x0F) * 4;
        char srcIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ipHeader->srcIP, srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ipHeader->destIP, destIP, INET_ADDRSTRLEN);
        LOG_DEBUG("  IP: " << srcIP << " -> " << destIP);
        LOG_DEBUG("  Protocol: " << static_cast<int>(ipHeader->protocol));

        // Parse UDP header
        if (ipHeader->protocol != 17 || packetData.size() < sizeof(EthernetHeader) + ipHeaderLength + sizeof(UDPHeader)) {
            LOG_INFO("  Not a UDP packet or too short for UDP header");
            continue;
        }
        const UDPHeader* udpHeader = reinterpret_cast<const UDPHeader*>(packetData.data() + sizeof(EthernetHeader) + ipHeaderLength);
        uint16_t srcPort = ntohs(udpHeader->srcPort);
        uint16_t destPort = ntohs(udpHeader->destPort);
        LOG_DEBUG("  UDP: " << srcPort << " -> " << destPort);

        // Calculate offset to SIMBA data
        size_t simbaOffset = sizeof(EthernetHeader) + ipHeaderLength + sizeof(UDPHeader);
        size_t simbaLength = packetData.size() - simbaOffset;

        LOG_DEBUG("  SIMBA data offset: " << simbaOffset);
        LOG_DEBUG("  SIMBA data length: " << simbaLength);

        // Print first few bytes of the SIMBA data
        //LOG_DEBUG("  First 32 bytes of SIMBA data: ");
        //for (size_t i = 0; i < std::min(size_t(32), simbaLength); ++i) {
        //    LOG_DEBUG(std::hex << std::setw(2) << std::setfill('0') 
        //              << static_cast<int>(packetData[simbaOffset + i]) << " ");
        //}
        //LOG_DEBUG(std::dec);

        // Try to decode SIMBA message
        auto result = decoder.decodeMessage(packetData.data() + simbaOffset, simbaLength);
        if (result) {
            std::visit([](auto&& msg) {
                using T = std::decay_t<decltype(msg)>;
                if constexpr (std::is_same_v<T, OrderUpdate>) {
                    LOG_DEBUG("  Received OrderUpdate");
                } else if constexpr (std::is_same_v<T, OrderExecution>) {
                    LOG_DEBUG("  Received OrderExecution");
                } else if constexpr (std::is_same_v<T, OrderBookSnapshot>) {
                    LOG_DEBUG("  Received OrderBookSnapshot");
                }
            }, *result);
        } else {
            LOG_DEBUG("  Failed to decode message");
        }
    }
}    

private:
    std::ifstream file;
    PCAPFileHeader fileHeader;

void readFileHeader() {
    LOG_INFO("Attempting to read PCAP file header...");
    
    // Read first 24 bytes directly
    char buffer[24];
    file.read(buffer, 24);
    if (file.gcount() != 24) {
        throw std::runtime_error("Failed to read first 24 bytes. Bytes read: " + std::to_string(file.gcount()));
    }

    //LOG_DEBUG("First 24 bytes: ");
    //for (int i = 0; i < 24; ++i) {
    //    LOG_DEBUG(std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(buffer[i])) << " ");
    //}
    //LOG_DEBUG(std::dec);

    // Reset file position
    file.seekg(0, std::ios::beg);

    // Now try to read the full header
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(PCAPFileHeader));
    if (file.gcount() != sizeof(PCAPFileHeader)) {
        throw std::runtime_error("Failed to read PCAP file header. Bytes read: " + std::to_string(file.gcount()));
    }

    LOG_DEBUG("Magic number: 0x" << std::hex << fileHeader.magic_number << std::dec);

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

    LOG_INFO("Little-endian interpretation:");
    LOG_INFO("Magic number: 0x" << std::hex << leHeader.magic_number << std::dec);
    LOG_INFO("Version: " << leHeader.version_major << "." << leHeader.version_minor);
    LOG_INFO("Timezone offset: " << leHeader.thiszone);
    LOG_INFO("Timestamp accuracy: " << leHeader.sigfigs);
    LOG_INFO("Snapshot length: " << leHeader.snaplen);
    LOG_INFO("Network type: " << leHeader.network);

    LOG_INFO("\nBig-endian interpretation:");
    LOG_INFO("Magic number: 0x" << std::hex << beHeader.magic_number << std::dec);
    LOG_INFO("Version: " << beHeader.version_major << "." << beHeader.version_minor);
    LOG_INFO("Timezone offset: " << beHeader.thiszone);
    LOG_INFO("Timestamp accuracy: " << beHeader.sigfigs);
    LOG_INFO("Snapshot length: " << beHeader.snaplen);
    LOG_INFO("Network type: " << beHeader.network);

    // Choose the interpretation that looks more correct
    if (beHeader.magic_number == 0xa1b2c3d4 || beHeader.magic_number == 0xa1b23c4d) {
        fileHeader = beHeader;
        LOG_INFO("\nUsing big-endian interpretation");
    } else if (leHeader.magic_number == 0xa1b2c3d4 || leHeader.magic_number == 0xa1b23c4d) {
        fileHeader = leHeader;
        LOG_INFO("\nUsing little-endian interpretation");
    } else {
        throw std::runtime_error("Invalid PCAP file format. Unrecognized magic number.");
    }

    LOG_INFO("PCAP file header read successfully");
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
    LOG_DEBUG("Packet details:");
    LOG_DEBUG("  Ether Type: 0x" << std::hex << ntohs(ethHeader->etherType) << std::dec);
    LOG_DEBUG("  IP Protocol: " << static_cast<int>(ipHeader->protocol));
    LOG_DEBUG("  Source IP: " << (ntohl(ipHeader->srcIP) >> 24) << "." << ((ntohl(ipHeader->srcIP) >> 16) & 0xFF) << "."
              << ((ntohl(ipHeader->srcIP) >> 8) & 0xFF) << "." << (ntohl(ipHeader->srcIP) & 0xFF));
    LOG_DEBUG("  Dest IP: " << (ntohl(ipHeader->destIP) >> 24) << "." << ((ntohl(ipHeader->destIP) >> 16) & 0xFF) << "."
              << ((ntohl(ipHeader->destIP) >> 8) & 0xFF) << "." << (ntohl(ipHeader->destIP) & 0xFF));
    LOG_DEBUG("  Source Port: " << ntohs(udpHeader->srcPort));
    LOG_DEBUG("  Dest Port: " << ntohs(udpHeader->destPort));
    LOG_DEBUG("  SIMBA data length: " << simba_data_length);

    // Декодируем сообщение SIMBA SPECTRA
    auto decoded_message = decoder.decodeMessage(simba_data, simba_data_length);

    // Здесь вы можете обработать декодированное сообщение
    if (decoded_message) {
        std::visit([](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, OrderUpdate>) {
                LOG_DEBUG("Received OrderUpdate");
            } else if constexpr (std::is_same_v<T, OrderExecution>) {
                LOG_DEBUG("Received OrderExecution");
            } else if constexpr (std::is_same_v<T, OrderBookSnapshot>) {
                LOG_DEBUG("Received OrderBookSnapshot");
            }
        }, *decoded_message);
    } else {
        LOG_WARNING("Failed to decode message");
    }
}

};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        LOG_INFO("Usage: " << argv[0] << " <pcap_file>");
        return 1;
    }

    try {
        PCAPParser parser(argv[1]);
        SimbaDecoder decoder;
        parser.parsePackets(decoder);
	decoder.printStatistics();
    } catch (const std::exception& e) {
        LOG_ERROR("Error: " << e.what());
        return 1;
    }

    return 0;
}
