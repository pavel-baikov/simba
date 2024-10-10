#ifndef SIMBA_DECODER_H
#define SIMBA_DECODER_H

#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include <optional>
#include <variant>
#include <map>

enum class MDUpdateAction : uint8_t {
    New = 0,
    Change = 1,
    Delete = 2
};

enum class MDEntryType : char {
    Bid = '0',
    Offer = '1',
    EmptyBook = 'J'
};

using MDFlagsSet = uint64_t;
using MDFlags2Set = uint64_t;

struct Decimal5 {
    int64_t mantissa;
    static constexpr int exponent = -5;

    [[nodiscard]] constexpr double toDouble() const noexcept {
        return static_cast<double>(mantissa) / 100000.0;
    }
};

std::ostream& operator<<(std::ostream& os, const Decimal5& d);

#pragma pack(push, 1)
struct OrderBookEntry {
    int64_t MDEntryID;
    uint64_t TransactTime;
    Decimal5 MDEntryPx;
    int64_t MDEntrySize;
    int64_t TradeID;
    MDFlagsSet MDFlags;
    MDFlags2Set MDFlags2;
    MDEntryType EntryType;
};

struct OrderUpdate {
    int64_t MDEntryID;
    Decimal5 MDEntryPx;
    int64_t MDEntrySize;
    MDFlagsSet MDFlags;
    MDFlags2Set MDFlags2;
    int32_t SecurityID;
    uint32_t RptSeq;
    MDUpdateAction UpdateAction;
    MDEntryType EntryType;
};

struct OrderExecution {
    int64_t MDEntryID;
    Decimal5 MDEntryPx;
    int64_t MDEntrySize;
    Decimal5 LastPx;
    int64_t LastQty;
    int64_t TradeID;
    MDFlagsSet MDFlags;
    MDFlags2Set MDFlags2;
    int32_t SecurityID;
    uint32_t RptSeq;
    MDUpdateAction UpdateAction;
    MDEntryType EntryType;
};

struct OrderBookSnapshot {
    int32_t SecurityID;
    uint32_t LastMsgSeqNumProcessed;
    uint32_t RptSeq;
    uint32_t ExchangeTradingSessionID;
    std::vector<OrderBookEntry> entries;
};

    struct MarketDataPacketHeader {
        uint32_t msgSeqNum;
        uint16_t msgSize;
        uint16_t msgFlags;
        uint64_t sendingTime;
    };

    struct IncrementalPacketHeader {
        uint64_t transactTime;
        uint32_t exchangeTradingSessionID;
    };

    struct SBEHeader {
        uint16_t blockLength;
        uint16_t templateId;
        uint16_t schemaId;
        uint16_t version;
    };

    struct FragmentedMessage {
        std::vector<std::vector<uint8_t>> fragments;
        uint64_t transactTime;
        uint16_t templateId;
        bool isComplete;
    };
#pragma pack(pop)

using DecodedMessage = std::variant<OrderUpdate, OrderExecution, OrderBookSnapshot>;

class SimbaDecoder {
public:
    SimbaDecoder() = default;
    ~SimbaDecoder() = default;

    SimbaDecoder(const SimbaDecoder&) = delete;
    SimbaDecoder& operator=(const SimbaDecoder&) = delete;
    SimbaDecoder(SimbaDecoder&&) = default;
    SimbaDecoder& operator=(SimbaDecoder&&) = default;

    // Main decoding method
    [[nodiscard]] std::optional<DecodedMessage> decodeMessage(const uint8_t* data, size_t length);

    // Method to save decoded data
    void saveDecodedData(const std::string& filename) const;

private:
    MarketDataPacketHeader decodeMarketDataPacketHeader(const uint8_t* data);
    IncrementalPacketHeader decodeIncrementalPacketHeader(const uint8_t* data);
    SBEHeader decodeSBEHeader(const uint8_t* data);

    std::map<std::pair<int32_t, uint16_t>, FragmentedMessage> fragmentedMessages;

    std::optional<DecodedMessage> processFragment(const uint8_t* data, size_t length, uint16_t msgFlags, uint64_t transactTime, uint16_t templateId);
    std::optional<DecodedMessage> decodeFullMessage(const uint8_t* data, size_t length, uint16_t templateId);

    // Specialized decoding methods
    [[nodiscard]] OrderUpdate decodeOrderUpdate(const uint8_t* data, size_t length) const;
    [[nodiscard]] OrderExecution decodeOrderExecution(const uint8_t* data, size_t length) const;
    [[nodiscard]] OrderBookSnapshot decodeOrderBookSnapshot(const uint8_t* data, size_t length) const;

    // Helper methods for decoding
    static uint16_t decodeUInt16(const uint8_t* data) noexcept;
    static uint32_t decodeUInt32(const uint8_t* data) noexcept;
    static uint64_t decodeUInt64(const uint8_t* data) noexcept;
    static int32_t decodeInt32(const uint8_t* data) noexcept;
    static int64_t decodeInt64(const uint8_t* data) noexcept;
    static Decimal5 decodeDecimal5(const uint8_t* data) noexcept;

    // Helper method to parse message header
    static void parseHeader(const uint8_t* data, uint16_t& blockLength, uint16_t& templateId, 
                            uint16_t& schemaId, uint16_t& version) noexcept;
};

#endif // SIMBA_DECODER_H
