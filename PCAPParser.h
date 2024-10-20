// PCAPParser.h

#ifndef PCAP_PARSER_H
#define PCAP_PARSER_H

#include <fstream>
#include <vector>

#include "SimbaDecoder.h"

// Structures for PCAP file headers
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

// Structures for network protocol headers
struct EthernetHeader {
	uint8_t destMac[6];
	uint8_t srcMac[6];
	uint16_t etherType;
};

struct IPHeader {
	uint8_t versionIHL;
	uint8_t typeOfService;
	uint16_t totalLength;
	uint16_t identification;
	uint16_t flagsFragmentOffset;
	uint8_t timeToLive;
	uint8_t protocol;
	uint16_t headerChecksum;
	uint32_t srcIP;
	uint32_t destIP;
};

struct UDPHeader {
	uint16_t srcPort;
	uint16_t destPort;
	uint16_t length;
	uint16_t checksum;
};

static constexpr uint16_t SIMBA_PORT = 44040; // Replace with the actual port
static constexpr uint32_t SIMBA_MULTICAST_IP = 0xEFC31452; // 239.195.20.82 in network byte order

class PCAPParser {
	public:
		PCAPParser(const std::string& filename);
		void parsePackets(SimbaDecoder& decoder);
		bool isValid() const { return is_valid; }
	private:
		void readFileHeader();
		void processPacket(const std::vector<unsigned char>& packet_data, SimbaDecoder& decoder);

		std::ifstream file;
		PCAPFileHeader fileHeader;
		bool is_valid = false;
};

#endif // PCAP_PARSER_H

