#include "PCAPParser.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <cstdint>
#include <arpa/inet.h>
#include <variant>

#include "log.h"

PCAPParser::PCAPParser(const std::string& filename) : file(filename, std::ios::binary) {
	if (!file.is_open()) {
		LOG_ERROR("Cannot open file: " << filename);
		return;
	}
	LOG_INFO("File opened successfully: " << filename);

	// Get file size
	file.seekg(0, std::ios::end);
	std::streampos fileSize = file.tellg();
	file.seekg(0, std::ios::beg);
	LOG_INFO("File size: " << fileSize << " bytes");

	readFileHeader();
}

void PCAPParser::parsePackets(SimbaDecoder& decoder) {
	PCAPPacketHeader packetHeader;
	std::vector<uint8_t> packetData;
	int packetCount [[maybe_unused]] = 0;

	while (file.read(reinterpret_cast<char*>(&packetHeader), sizeof(PCAPPacketHeader))) {
		packetHeader.ts_sec = le32toh(packetHeader.ts_sec);
		packetHeader.ts_usec = le32toh(packetHeader.ts_usec);
		packetHeader.incl_len = le32toh(packetHeader.incl_len);
		packetHeader.orig_len = le32toh(packetHeader.orig_len);

		packetData.resize(packetHeader.incl_len);
		if (!file.read(reinterpret_cast<char*>(packetData.data()), packetHeader.incl_len)) {
			LOG_ERROR("Failed to read packet data");
			return;
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
		uint16_t srcPort [[maybe_unused]] = ntohs(udpHeader->srcPort);
		uint16_t destPort [[maybe_unused]] = ntohs(udpHeader->destPort);
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

void PCAPParser::readFileHeader() {
	LOG_INFO("Attempting to read PCAP file header...");

	file.read(reinterpret_cast<char*>(&fileHeader), sizeof(PCAPFileHeader));
	if (file.gcount() != sizeof(PCAPFileHeader)) {
        	LOG_ERROR("Failed to read PCAP file header. Bytes read: " << file.gcount());
        	return;
	}

	LOG_INFO("Magic number: 0x" << std::hex << fileHeader.magic_number << std::dec);
	LOG_INFO("Version: " << fileHeader.version_major << "." << fileHeader.version_minor);
	LOG_INFO("Timezone offset: " << fileHeader.thiszone);
	LOG_INFO("Timestamp accuracy: " << fileHeader.sigfigs);
	LOG_INFO("Snapshot length: " << fileHeader.snaplen);
	LOG_INFO("Network type: " << fileHeader.network);

	// Choose the interpretation that looks more correct
	if (fileHeader.magic_number == 0xa1b2c3d4 || fileHeader.magic_number == 0xa1b23c4d) {
		is_valid = true;
	} else {
        	LOG_ERROR("Invalid PCAP file format. Unrecognized magic number.");
        	return;			
	}

	LOG_INFO("PCAP file header read successfully");
}    

void PCAPParser::processPacket(const std::vector<unsigned char>& packet_data, SimbaDecoder& decoder) {
	if (packet_data.size() < sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader)) {
		return; // Packet is too short
	}

	const EthernetHeader* ethHeader = reinterpret_cast<const EthernetHeader*>(packet_data.data());
	if (ntohs(ethHeader->etherType) != 0x0800) {
		return; // Not an IP packet
	}

	const IPHeader* ipHeader = reinterpret_cast<const IPHeader*>(packet_data.data() + sizeof(EthernetHeader));
	if (ipHeader->protocol != 17) {
		return; // Not a UDP packet
	}

	const UDPHeader* udpHeader = reinterpret_cast<const UDPHeader*>(packet_data.data() + sizeof(EthernetHeader) + (ipHeader->versionIHL & 0x0F) * 4);
	if (ntohs(udpHeader->destPort) != SIMBA_PORT || ntohl(ipHeader->destIP) != SIMBA_MULTICAST_IP) {
		return; // Not a SIMBA SPECTRA packet
	}

	// Get a pointer to the start of SIMBA SPECTRA data
	const uint8_t* simba_data = packet_data.data() + sizeof(EthernetHeader) + (ipHeader->versionIHL & 0x0F) * 4 + sizeof(UDPHeader);

	// Get the length of SIMBA SPECTRA data
	size_t simba_data_length = ntohs(udpHeader->length) - sizeof(UDPHeader);

	// Output debug information
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

	// Decoding the SIMBA SPECTRA message
	auto decoded_message = decoder.decodeMessage(simba_data, simba_data_length);

	// Here you can process the decoded message
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

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    Logger::init_log("simba.log");

    PCAPParser parser(argv[1]);
    if (!parser.isValid()) {
        LOG_ERROR("Failed to initialize PCAPParser");
        Logger::close_log();
        return 1;
    }

    SimbaDecoder decoder;
    parser.parsePackets(decoder);

    decoder.printStatistics();

    Logger::close_log();
    return 0;
}
