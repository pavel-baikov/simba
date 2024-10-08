#include "SimbaDecoder.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <cstring>

std::ostream& operator<<(std::ostream& os, const Decimal5& d) {
    return os << d.toDouble();
}

bool isFragmented(uint16_t msgFlags) {
    bool lastFragment = msgFlags & 0x1;
    bool startOfSnapshot = msgFlags & 0x2;
    bool endOfSnapshot = msgFlags & 0x4;

    // Если это не последний фрагмент, или это начало/конец снэпшота, 
    // то сообщение фрагментировано
    return !lastFragment || startOfSnapshot || endOfSnapshot;
}

MarketDataPacketHeader SimbaDecoder::decodeMarketDataPacketHeader(const uint8_t* data) {
    MarketDataPacketHeader header;
    size_t offset = 0;

    header.msgSeqNum = decodeUInt32(data + offset);
    offset += 4;

    header.msgSize = decodeUInt16(data + offset);
    offset += 2;

    header.msgFlags = decodeUInt16(data + offset);
    offset += 2;

    header.sendingTime = decodeUInt64(data + offset);

    // Логирование распарсенных данных
    std::cout << "Decoded Market Data Packet Header:" << std::endl;
    std::cout << "  MsgSeqNum: " << header.msgSeqNum << std::endl;
    std::cout << "  MsgSize: " << header.msgSize << std::endl;
    std::cout << "  MsgFlags: 0x" << std::hex << header.msgFlags << std::dec << std::endl;
    std::cout << "  SendingTime: " << header.sendingTime << std::endl;

    // Дополнительная расшифровка MsgFlags
    std::cout << "  MsgFlags details:" << std::endl;
    std::cout << "    LastFragment: " << ((header.msgFlags & 0x01) ? "Yes" : "No") << std::endl;
    std::cout << "    StartOfSnapshot: " << ((header.msgFlags & 0x02) ? "Yes" : "No") << std::endl;
    std::cout << "    EndOfSnapshot: " << ((header.msgFlags & 0x04) ? "Yes" : "No") << std::endl;
    std::cout << "    IncrementalPacket: " << ((header.msgFlags & 0x08) ? "Yes" : "No") << std::endl;

    return header;
}

IncrementalPacketHeader SimbaDecoder::decodeIncrementalPacketHeader(const uint8_t* data) {
    IncrementalPacketHeader header;
    header.transactTime = decodeUInt64(data);
    header.exchangeTradingSessionID = decodeUInt32(data + 8);

    // Логирование распарсенных данных
    std::cout << "Decoded Incremental Packet Header:" << std::endl;
    std::cout << "  TransactTime: " << header.transactTime << std::endl;
    std::cout << "  ExchangeTradingSessionID: " << header.exchangeTradingSessionID << std::endl;

    // Дополнительная информация о TransactTime
    time_t seconds = header.transactTime / 1000000000; // Наносекунды в секунды
    struct tm *timeinfo = localtime(&seconds);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    std::cout << "  TransactTime (human-readable): " << buffer 
              << "." << std::setfill('0') << std::setw(9) 
              << header.transactTime % 1000000000 << std::endl;

    return header;
}

/*
std::optional<DecodedMessage> SimbaDecoder::decodeMessage(const uint8_t* data, size_t length) {

    //декодировать MarketDataPacketHeader
    if (length < 28) {  // 16 байт Market Data Packet Header + 12 байт Incremental Packet Header
        std::cout << "Message too short to contain a valid header" << std::endl;
        return std::nullopt;
    }

    // Декодирование Market Data Packet Header
    MarketDataPacketHeader header = decodeMarketDataPacketHeader(data);

    // Проверка на фрагментацию
    if (isFragmented(header.msgFlags)) {
        std::cout << "  Fragmented message detected!" << std::endl;
        std::cout << "  LastFragment: " << (header.msgFlags & 0x1 ? "Yes" : "No") << std::endl;
        std::cout << "  StartOfSnapshot: " << (header.msgFlags & 0x2 ? "Yes" : "No") << std::endl;
        std::cout << "  EndOfSnapshot: " << (header.msgFlags & 0x4 ? "Yes" : "No") << std::endl;
    } else {
        std::cout << "  Non-fragmented message" << std::endl;
    }    

    // Вывод первых 32 байт сообщения
    std::cout << "message: ";
    for (int i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << " ";
    }
    std::cout << std::dec << std::endl;

    // Читаем MsgFlags из Market Data Packet Header
    uint16_t msgFlags = *reinterpret_cast<const uint16_t*>(data + 6);
    bool isIncrementalPacket = (msgFlags & 0x08) != 0;

    // Определяем смещение до SBE Header
    size_t offset = isIncrementalPacket ? 28 : 16;

    if (length < offset + 8) {  // 8 байт для SBE Header
        std::cout << "Message too short to contain SBE Header" << std::endl;
        return std::nullopt;
    }

    // Читаем SBE Header
    const uint8_t* sbeHeader = data + offset;
    uint16_t blockLength = *reinterpret_cast<const uint16_t*>(sbeHeader);
    uint16_t templateId = *reinterpret_cast<const uint16_t*>(sbeHeader + 2);
    uint16_t schemaId = *reinterpret_cast<const uint16_t*>(sbeHeader + 4);
    uint16_t version = *reinterpret_cast<const uint16_t*>(sbeHeader + 6);

    std::cout << "Block Length: " << blockLength << std::endl;
    std::cout << "Template ID: " << templateId << std::endl;
    std::cout << "Schema ID: " << schemaId << std::endl;
    std::cout << "Version: " << version << std::endl;

    // Переходим к данным сообщения
    const uint8_t* messageData = sbeHeader + 8;
    size_t messageLength = length - (offset + 8);

    switch (templateId) {
        //case 14:
        //    return decodeBestPrices(messageData, messageLength);
        case 15:
            return decodeOrderUpdate(messageData, messageLength);
        case 16:
            return decodeOrderExecution(messageData, messageLength);
        case 17:
            return decodeOrderBookSnapshot(messageData, messageLength);
        default:
            std::cerr << "Unknown template ID: " << templateId << std::endl;
            return std::nullopt;
    }
}
*/

SBEHeader SimbaDecoder::decodeSBEHeader(const uint8_t* data) {
    SBEHeader header;
    size_t offset = 0;

    header.blockLength = decodeUInt16(data + offset);
    offset += 2;

    header.templateId = decodeUInt16(data + offset);
    offset += 2;

    header.schemaId = decodeUInt16(data + offset);
    offset += 2;

    header.version = decodeUInt16(data + offset);

    // Логирование распарсенных данных
    std::cout << "Decoded SBE Header:" << std::endl;
    std::cout << "  BlockLength: " << header.blockLength << std::endl;
    std::cout << "  TemplateID: " << header.templateId << std::endl;
    std::cout << "  SchemaID: " << header.schemaId << std::endl;
    std::cout << "  Version: " << header.version << std::endl;

    // Дополнительная информация о TemplateID
    std::cout << "  TemplateID details:" << std::endl;
    switch (header.templateId) {
        case 15:
            std::cout << "    Message type: OrderUpdate" << std::endl;
            break;
        case 16:
            std::cout << "    Message type: OrderExecution" << std::endl;
            break;
        case 17:
            std::cout << "    Message type: OrderBookSnapshot" << std::endl;
            break;
        default:
            std::cout << "    Message type: Unknown" << std::endl;
    }

    return header;
}

std::optional<DecodedMessage> SimbaDecoder::decodeMessage(const uint8_t* data, size_t length) {
    if (length < sizeof(MarketDataPacketHeader)) {
        std::cout << "Message too short to contain a valid header" << std::endl;
        return std::nullopt;
    }

    std::cout << "message: ";
    for (int i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << " ";
    }
    std::cout << std::dec << std::endl;    

    MarketDataPacketHeader mdHeader = decodeMarketDataPacketHeader(data);
    size_t offset = sizeof(MarketDataPacketHeader);

    bool isIncrementalPacket = (mdHeader.msgFlags & 0x08) != 0;
    bool isLastFragment = (mdHeader.msgFlags & 0x01) != 0;
    bool isStartOfSnapshot = (mdHeader.msgFlags & 0x02) != 0;
    bool isEndOfSnapshot = (mdHeader.msgFlags & 0x04) != 0;

    uint64_t transactTime = 0;
    if (isIncrementalPacket) {
        if (length < offset + sizeof(IncrementalPacketHeader)) {
            std::cout << "Message too short to contain Incremental Packet Header" << std::endl;
            return std::nullopt;
        }
        IncrementalPacketHeader incHeader = decodeIncrementalPacketHeader(data + offset);
        transactTime = incHeader.transactTime;
        offset += sizeof(IncrementalPacketHeader);
    }

    if (length < offset + sizeof(SBEHeader)) {
        std::cout << "Message too short to contain SBE Header" << std::endl;
        return std::nullopt;
    }

    SBEHeader sbeHeader = decodeSBEHeader(data + offset);
    offset += sizeof(SBEHeader);

    // Раннее отсеивание ненужных типов сообщений
    switch (sbeHeader.templateId) {
        case 15: // OrderUpdate
        case 16: // OrderExecution
        case 17: // OrderBookSnapshot
            break;
        default:
            std::cout << "Ignoring message with TemplateID: " << sbeHeader.templateId << std::endl;
            return std::nullopt;
    }

    return processFragment(data + offset, length - offset, mdHeader.msgFlags, transactTime, sbeHeader.templateId);
}

std::optional<DecodedMessage> SimbaDecoder::processFragment(const uint8_t* data, size_t length, 
                                                            uint16_t msgFlags, uint64_t transactTime, 
                                                            uint16_t templateId) {
    bool isLastFragment = (msgFlags & 0x01) != 0;
    bool isStartOfSnapshot = (msgFlags & 0x02) != 0;
    bool isEndOfSnapshot = (msgFlags & 0x04) != 0;

    int32_t securityId = decodeInt32(data);

    std::cout << "processFragment templateId = " << templateId << " securityId = " << securityId << std::endl;

    std::pair<int32_t, uint16_t> key(securityId, templateId);

    if (!isLastFragment || isStartOfSnapshot || isEndOfSnapshot) {
        auto& fragMsg = fragmentedMessages[key];
        fragMsg.fragments.push_back(std::vector<uint8_t>(data, data + length));
        fragMsg.transactTime = transactTime;
        fragMsg.templateId = templateId;
        fragMsg.isComplete = isLastFragment || isEndOfSnapshot;

        if (!fragMsg.isComplete) {
            return std::nullopt;
        }

        std::vector<uint8_t> fullMessage;
        for (const auto& fragment : fragMsg.fragments) {
            fullMessage.insert(fullMessage.end(), fragment.begin(), fragment.end());
        }
        fragmentedMessages.erase(key);

        return decodeFullMessage(fullMessage.data(), fullMessage.size(), templateId);
    }

    return decodeFullMessage(data, length, templateId);
}

std::optional<DecodedMessage> SimbaDecoder::decodeFullMessage(const uint8_t* data, size_t length, uint16_t templateId) {
    switch (templateId) {
        case 15:
            return decodeOrderUpdate(data, length);
        case 16:
            return decodeOrderExecution(data, length);
        case 17:
            return decodeOrderBookSnapshot(data, length);
        default:
            std::cerr << "Unknown template ID: " << templateId << std::endl;
            return std::nullopt;
    }
}

OrderUpdate SimbaDecoder::decodeOrderUpdate(const uint8_t* data, size_t length) const {
    if (length < 50) {
        throw std::runtime_error("OrderUpdate message too short");
    }

    OrderUpdate update;
    size_t offset = 0;

    update.MDEntryID = decodeInt64(data + offset);
    offset += 8;

    update.MDEntryPx = decodeDecimal5(data + offset);
    offset += 8;

    update.MDEntrySize = decodeInt64(data + offset);
    offset += 8;

    update.MDFlags = decodeUInt64(data + offset);
    offset += 8;

    update.MDFlags2 = decodeUInt64(data + offset);
    offset += 8;

    update.SecurityID = decodeInt32(data + offset);
    offset += 4;

    update.RptSeq = decodeUInt32(data + offset);
    offset += 4;

    update.UpdateAction = static_cast<MDUpdateAction>(data[offset]);
    offset += 1;

    update.EntryType = static_cast<MDEntryType>(data[offset]);

    // Отладочный вывод
    std::cout << "Decoded OrderUpdate: "
              << "MDEntryID=" << update.MDEntryID
              << ", MDEntryPx=" << update.MDEntryPx
              << ", MDEntrySize=" << update.MDEntrySize
              << ", SecurityID=" << update.SecurityID
              << ", RptSeq=" << update.RptSeq
              << ", UpdateAction=" << static_cast<int>(update.UpdateAction)
              << ", EntryType=" << static_cast<char>(update.EntryType)
              << std::endl;

    return update;
}

OrderExecution SimbaDecoder::decodeOrderExecution(const uint8_t* data, size_t /*length*/) const {
    OrderExecution execution;
    size_t offset = 0;

    execution.MDEntryID = decodeInt64(data + offset);
    offset += 8;

    execution.MDEntryPx = decodeDecimal5(data + offset);
    offset += 8;

    execution.MDEntrySize = decodeInt64(data + offset);
    offset += 8;

    execution.LastPx = decodeDecimal5(data + offset);
    offset += 8;

    execution.LastQty = decodeInt64(data + offset);
    offset += 8;

    execution.TradeID = decodeInt64(data + offset);
    offset += 8;

    execution.MDFlags = decodeUInt64(data + offset);
    offset += 8;

    execution.MDFlags2 = decodeUInt64(data + offset);
    offset += 8;

    execution.SecurityID = decodeInt32(data + offset);
    offset += 4;

    execution.RptSeq = decodeUInt32(data + offset);
    offset += 4;

    execution.UpdateAction = static_cast<MDUpdateAction>(data[offset]);
    offset += 1;

    execution.EntryType = static_cast<MDEntryType>(data[offset]);

    return execution;
}

OrderBookSnapshot SimbaDecoder::decodeOrderBookSnapshot(const uint8_t* data, size_t /*length*/) const {
    OrderBookSnapshot snapshot;
    size_t offset = 0;

    snapshot.SecurityID = decodeInt32(data + offset);
    offset += 4;

    snapshot.LastMsgSeqNumProcessed = decodeUInt32(data + offset);
    offset += 4;

    snapshot.RptSeq = decodeUInt32(data + offset);
    offset += 4;

    snapshot.ExchangeTradingSessionID = decodeUInt32(data + offset);
    offset += 4;

    //uint16_t blockLength = decodeUInt16(data + offset);
    offset += 2;

    uint8_t noMDEntries = data[offset];
    offset += 1;

    snapshot.entries.reserve(noMDEntries);

    for (int i = 0; i < noMDEntries; ++i) {
        OrderBookEntry entry;
        
        entry.MDEntryID = decodeInt64(data + offset);
        offset += 8;

        entry.TransactTime = decodeUInt64(data + offset);
        offset += 8;

        entry.MDEntryPx = decodeDecimal5(data + offset);
        offset += 8;

        entry.MDEntrySize = decodeInt64(data + offset);
        offset += 8;

        entry.TradeID = decodeInt64(data + offset);
        offset += 8;

        entry.MDFlags = decodeUInt64(data + offset);
        offset += 8;

        entry.MDFlags2 = decodeUInt64(data + offset);
        offset += 8;

        entry.EntryType = static_cast<MDEntryType>(data[offset]);
        offset += 1;

        snapshot.entries.push_back(entry);
    }

std::cout << "OrderBookSnapshot: "
          << "SecurityID=" << snapshot.SecurityID
          << ", LastMsgSeqNumProcessed=" << snapshot.LastMsgSeqNumProcessed
          << ", RptSeq=" << snapshot.RptSeq
          << ", ExchangeTradingSessionID=" << snapshot.ExchangeTradingSessionID
          << ", Entries=" << snapshot.entries.size() << std::endl;
for (const auto& entry : snapshot.entries) {
    std::cout << "  Entry: MDEntryID=" << entry.MDEntryID
              << ", MDEntryPx=" << entry.MDEntryPx
              << ", MDEntrySize=" << entry.MDEntrySize
              << ", EntryType=" << static_cast<char>(entry.EntryType) << std::endl;
}    

    return snapshot;
}

uint16_t SimbaDecoder::decodeUInt16(const uint8_t* data) noexcept {
    uint16_t value;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

uint32_t SimbaDecoder::decodeUInt32(const uint8_t* data) noexcept {
    uint32_t value;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

uint64_t SimbaDecoder::decodeUInt64(const uint8_t* data) noexcept {
    uint64_t value;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

int32_t SimbaDecoder::decodeInt32(const uint8_t* data) noexcept {
    int32_t value;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

int64_t SimbaDecoder::decodeInt64(const uint8_t* data) noexcept {
    int64_t value;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

Decimal5 SimbaDecoder::decodeDecimal5(const uint8_t* data) noexcept {
    Decimal5 value;
    value.mantissa = decodeInt64(data);
    return value;
}

void SimbaDecoder::parseHeader(const uint8_t* data, uint16_t& blockLength, uint16_t& templateId,
                               uint16_t& schemaId, uint16_t& version) noexcept {
    blockLength = decodeUInt16(data);
    templateId = decodeUInt16(data + 2);
    schemaId = decodeUInt16(data + 4);
    version = decodeUInt16(data + 6);
}

void SimbaDecoder::saveDecodedData(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Unable to open file: " << filename << std::endl;
        return;
    }

    file << "Decoded data will be saved here.\n";
    // Implement the logic to save decoded data

    file.close();
}
