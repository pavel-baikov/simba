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

SBEHeader SimbaDecoder::decodeSBEHeader(const uint8_t* data) const {
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
    for (size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << " ";
    }
    std::cout << std::dec << std::endl;

    MarketDataPacketHeader mdHeader = decodeMarketDataPacketHeader(data);
    size_t offset = sizeof(MarketDataPacketHeader);

    std::cout << "sizeof(MarketDataPacketHeader) = " << sizeof(MarketDataPacketHeader) << std::endl;

    bool isIncrementalPacket = (mdHeader.msgFlags & 0x08) != 0;
    bool isLastFragment = (mdHeader.msgFlags & 0x01) != 0;
    bool isStartOfSnapshot = (mdHeader.msgFlags & 0x02) != 0;
    bool isEndOfSnapshot = (mdHeader.msgFlags & 0x04) != 0;

    std::cout << "Message Flags Analysis:" << std::endl;
    std::cout << "  Raw MsgFlags: 0x" << std::hex << std::setw(4) << std::setfill('0') << mdHeader.msgFlags << std::dec << std::endl;
    std::cout << "  IsIncrementalPacket: " << (isIncrementalPacket ? "Yes" : "No") << std::endl;
    std::cout << "  IsLastFragment: " << (isLastFragment ? "Yes" : "No") << std::endl;
    std::cout << "  IsStartOfSnapshot: " << (isStartOfSnapshot ? "Yes" : "No") << std::endl;
    std::cout << "  IsEndOfSnapshot: " << (isEndOfSnapshot ? "Yes" : "No") << std::endl;

    uint64_t transactTime = 0;
    if (isIncrementalPacket) {
        if (length < offset + sizeof(IncrementalPacketHeader)) {
            std::cout << "Message too short to contain Incremental Packet Header" << std::endl;
            return std::nullopt;
        }
        IncrementalPacketHeader incHeader = decodeIncrementalPacketHeader(data + offset);
        transactTime = incHeader.transactTime;
        offset += sizeof(IncrementalPacketHeader);

        std::cout << "offset = " << offset << " sizeof(IncrementalPacketHeader) = " << sizeof(IncrementalPacketHeader) << std::endl;
    }

    if (length < offset + sizeof(SBEHeader)) {
        std::cout << "Message too short to contain SBE Header" << std::endl;
        return std::nullopt;
    }

    std::cout << "Initial SBE Header:" << std::endl;
    SBEHeader sbeHeader = decodeSBEHeader(data + offset);

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
    std::cout << "Entering processFragment" << std::endl;
    std::cout << "  Length: " << length << std::endl;
    std::cout << "  MsgFlags: 0x" << std::hex << msgFlags << std::dec << std::endl;
    std::cout << "  TransactTime: " << transactTime << std::endl;
    std::cout << "  TemplateId: " << templateId << std::endl;

    bool isLastFragment = (msgFlags & 0x01) != 0;
    bool isStartOfSnapshot = (msgFlags & 0x02) != 0;
    bool isEndOfSnapshot = (msgFlags & 0x04) != 0;
    bool isIncrementalPacket = (msgFlags & 0x08) != 0;

    std::cout << "  IsLastFragment: " << (isLastFragment ? "Yes" : "No") << std::endl;
    std::cout << "  IsStartOfSnapshot: " << (isStartOfSnapshot ? "Yes" : "No") << std::endl;
    std::cout << "  IsEndOfSnapshot: " << (isEndOfSnapshot ? "Yes" : "No") << std::endl;
    std::cout << "  IsIncrementalPacket: " << (isIncrementalPacket ? "Yes" : "No") << std::endl;

    int32_t securityId = decodeInt32(data);
    std::cout << "  SecurityId: " << securityId << std::endl;

    std::pair<int32_t, uint16_t> key(securityId, templateId);

    if (isIncrementalPacket) {
        return processIncrementalPacket(data, length, isLastFragment, templateId, key);
    } else {
        return processSnapshotPacket(data, length, isStartOfSnapshot, isEndOfSnapshot, templateId, key);
    }
}

std::optional<DecodedMessage> SimbaDecoder::processIncrementalPacket(const uint8_t* data, size_t length,
                                                                     bool isLastFragment, uint16_t templateId,
                                                                     const std::pair<int32_t, uint16_t>& key) {
    if (!isLastFragment) {
        // Добавляем фрагмент к текущей транзакции
        auto& fragMsg = fragmentedMessages[key];
        fragMsg.fragments.push_back(std::vector<uint8_t>(data, data + length));
        std::cout << "Added incremental fragment. Total fragments: " << fragMsg.fragments.size() << std::endl;
        return std::nullopt;
    } else {
        // Последний фрагмент или целое сообщение
        std::vector<uint8_t> fullMessage(data, data + length);
        if (fragmentedMessages.count(key) > 0) {
            auto& fragMsg = fragmentedMessages[key];
            for (const auto& fragment : fragMsg.fragments) {
                fullMessage.insert(fullMessage.begin(), fragment.begin(), fragment.end());
            }
            fragmentedMessages.erase(key);
        }
        std::cout << "Processing complete incremental message. Size: " << fullMessage.size() << std::endl;
        
        return decodeIncrementalPacket(fullMessage.data(), fullMessage.size());
    }
}

std::optional<DecodedMessage> SimbaDecoder::processSnapshotPacket(const uint8_t* data, size_t length,
                                                                  bool isStartOfSnapshot, bool isEndOfSnapshot,
                                                                  uint16_t templateId,
                                                                  const std::pair<int32_t, uint16_t>& key) {
    if (isStartOfSnapshot && isEndOfSnapshot) {
        // Полный снапшот в одном пакете
        std::cout << "Processing complete snapshot in single packet" << std::endl;
        auto [snapshots, size] = decodeOrderBookSnapshot(data, length);
        if (!snapshots.empty()) {
            return DecodedMessage(snapshots[0]);
        }
    } else if (isStartOfSnapshot) {
        // Начало нового снапшота
        fragmentedMessages[key].fragments.clear();
        fragmentedMessages[key].fragments.push_back(std::vector<uint8_t>(data, data + length));
        std::cout << "Started new snapshot. Fragment size: " << length << std::endl;
    } else if (isEndOfSnapshot) {
        // Конец снапшота
        auto& fragMsg = fragmentedMessages[key];
        fragMsg.fragments.push_back(std::vector<uint8_t>(data, data + length));
        std::vector<uint8_t> fullMessage;
        for (const auto& fragment : fragMsg.fragments) {
            fullMessage.insert(fullMessage.end(), fragment.begin(), fragment.end());
        }
        fragmentedMessages.erase(key);
        std::cout << "Completed snapshot. Total size: " << fullMessage.size() << std::endl;
        auto [snapshots, size] = decodeOrderBookSnapshot(fullMessage.data(), fullMessage.size());
        if (!snapshots.empty()) {
            return DecodedMessage(snapshots[0]);
        }
    } else {
        // Промежуточный фрагмент снапшота
        fragmentedMessages[key].fragments.push_back(std::vector<uint8_t>(data, data + length));
        std::cout << "Added snapshot fragment. Total fragments: " << fragmentedMessages[key].fragments.size() << std::endl;
    }

    return std::nullopt;
}

std::optional<DecodedMessage> SimbaDecoder::decodeIncrementalPacket(const uint8_t* data, size_t length) const {
    std::vector<OrderUpdate> updates;
    std::vector<OrderExecution> executions;
    size_t offset = 0;

    while (offset < length) {
        if (offset + sizeof(SBEHeader) > length) {
            std::cout << "Insufficient data for SBE Header. Remaining: " 
                      << (length - offset) << ", Required: " << sizeof(SBEHeader) << std::endl;
            break;
        }

        SBEHeader sbeHeader = decodeSBEHeader(data + offset);
        offset += sizeof(SBEHeader);

        std::cout << "Decoded SBE Header:" << std::endl
                  << "  BlockLength: " << sbeHeader.blockLength << std::endl
                  << "  TemplateID: " << sbeHeader.templateId << std::endl
                  << "  SchemaID: " << sbeHeader.schemaId << std::endl
                  << "  Version: " << sbeHeader.version << std::endl;

        if (offset + sbeHeader.blockLength > length) {
            std::cout << "Insufficient data for message block. Remaining: " 
                      << (length - offset) << ", Required: " << sbeHeader.blockLength << std::endl;
            break;
        }

        switch (sbeHeader.templateId) {
            case 15: // OrderUpdate
                {
                    OrderUpdate update = decodeOrderUpdate(data + offset, sbeHeader.blockLength);
                    updates.push_back(update);
                    offset += sbeHeader.blockLength;
                }
                break;
            case 16: // OrderExecution
                {
                    OrderExecution execution = decodeOrderExecution(data + offset, sbeHeader.blockLength);
                    executions.push_back(execution);
                    offset += sbeHeader.blockLength;
                }
                break;
            default:
                std::cout << "Unknown templateId in incremental packet: " << sbeHeader.templateId << std::endl;
                // Пропускаем неизвестный блок
                offset += sbeHeader.blockLength;
                break;
        }
    }

    if (offset < length) {
        std::cout << "Warning: " << (length - offset) << " bytes remaining after processing incremental packet" << std::endl;
    }

    if (!updates.empty()) {
        return DecodedMessage(updates[0]);  // Возвращаем первое обновление
    } else if (!executions.empty()) {
        return DecodedMessage(executions[0]);  // Возвращаем первое исполнение
    }

    return std::nullopt;
}

OrderUpdate SimbaDecoder::decodeOrderUpdate(const uint8_t* data, size_t length) const {
    std::cout << "Decoding OrderUpdate. Available length: " << length << std::endl;

    if (length < 50) { // минимальный размер OrderUpdate
        throw std::runtime_error("Insufficient data for OrderUpdate. Required: 50, Available: " + std::to_string(length));
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
    offset += 1;

    std::cout << "Decoded OrderUpdate:" << std::endl
              << "  MDEntryID: " << update.MDEntryID << std::endl
              << "  MDEntryPx: " << update.MDEntryPx.mantissa << "e" << update.MDEntryPx.exponent << std::endl
              << "  MDEntrySize: " << update.MDEntrySize << std::endl
              << "  MDFlags: 0x" << std::hex << update.MDFlags << std::dec << std::endl
              << "  MDFlags2: 0x" << std::hex << update.MDFlags2 << std::dec << std::endl
              << "  SecurityID: " << update.SecurityID << std::endl
              << "  RptSeq: " << update.RptSeq << std::endl
              << "  UpdateAction: " << static_cast<int>(update.UpdateAction) << std::endl
              << "  EntryType: " << static_cast<char>(update.EntryType) << std::endl;

    return update;
}

OrderExecution SimbaDecoder::decodeOrderExecution(const uint8_t* data, size_t length) const {
    std::cout << "Decoding OrderExecution. Available length: " << length << std::endl;

    if (length < 74) { // минимальный размер OrderExecution
        throw std::runtime_error("Insufficient data for OrderExecution. Required: 74, Available: " + std::to_string(length));
    }

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
    offset += 1;

    std::cout << "Decoded OrderExecution:" << std::endl
              << "  MDEntryID: " << execution.MDEntryID << std::endl
              << "  MDEntryPx: " << execution.MDEntryPx.mantissa << "e" << execution.MDEntryPx.exponent << std::endl
              << "  MDEntrySize: " << execution.MDEntrySize << std::endl
              << "  LastPx: " << execution.LastPx.mantissa << "e" << execution.LastPx.exponent << std::endl
              << "  LastQty: " << execution.LastQty << std::endl
              << "  TradeID: " << execution.TradeID << std::endl
              << "  MDFlags: 0x" << std::hex << execution.MDFlags << std::dec << std::endl
              << "  MDFlags2: 0x" << std::hex << execution.MDFlags2 << std::dec << std::endl
              << "  SecurityID: " << execution.SecurityID << std::endl
              << "  RptSeq: " << execution.RptSeq << std::endl
              << "  UpdateAction: " << static_cast<int>(execution.UpdateAction) << std::endl
              << "  EntryType: " << static_cast<char>(execution.EntryType) << std::endl;

    return execution;
}

std::pair<std::vector<OrderBookSnapshot>, size_t> SimbaDecoder::decodeOrderBookSnapshot(const uint8_t* data, size_t length) const {
    std::vector<OrderBookSnapshot> snapshots;
    size_t offset = 0;

    while (offset < length) {
        OrderBookSnapshot snapshot;
        size_t initialOffset = offset;

        // Декодирование заголовка
        if (length - offset < 19) {
            std::cerr << "Insufficient data for snapshot header at offset " << offset << std::endl;
            break;
        }

        snapshot.SecurityID = decodeInt32(data + offset);
        offset += 4;
        snapshot.LastMsgSeqNumProcessed = decodeUInt32(data + offset);
        offset += 4;
        snapshot.RptSeq = decodeUInt32(data + offset);
        offset += 4;
        snapshot.ExchangeTradingSessionID = decodeUInt32(data + offset);
        offset += 4;

        uint16_t blockLength = decodeUInt16(data + offset);
        offset += 2;
        uint8_t noMDEntries = data[offset];
        offset += 1;

        std::cout << "Decoding snapshot for SecurityID: " << snapshot.SecurityID
                  << ", NoMDEntries: " << static_cast<int>(noMDEntries)
                  << ", BlockLength: " << blockLength << std::endl;

        for (int i = 0; i < noMDEntries && offset < length; ++i) {
            if (length - offset < blockLength) {
                std::cerr << "Insufficient data for entry " << i + 1 << " at offset " << offset << std::endl;
                break;
            }

            OrderBookEntry entry = decodeOrderBookEntry(data + offset, blockLength);
            snapshot.entries.push_back(entry);
            offset += blockLength;
        }

        std::cout << "Snapshot decoded. Entries: " << snapshot.entries.size()
                  << ", Bytes processed: " << (offset - initialOffset) << std::endl;

        snapshots.push_back(snapshot);
    }

    std::cout << "Total snapshots decoded: " << snapshots.size()
              << ", Total bytes processed: " << offset
              << " out of " << length << std::endl;

    return {snapshots, offset};
}

OrderBookEntry SimbaDecoder::decodeOrderBookEntry(const uint8_t* data, [[maybe_unused]] size_t length) const {
    OrderBookEntry entry;
    size_t offset = 0;

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

    std::cout << "  MDEntryID: " << entry.MDEntryID
              << ", MDEntryPx: " << entry.MDEntryPx.mantissa << "e-5"
              << ", MDEntrySize: " << entry.MDEntrySize
              << ", EntryType: " << static_cast<char>(entry.EntryType) << std::endl;

    return entry;
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
