#include "SimbaDecoder.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <cstring>
#include <cassert>

#include "log.h"

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
    LOG_DEBUG("Decoded Market Data Packet Header:" );
    LOG_DEBUG("  MsgSeqNum: " << header.msgSeqNum );
    LOG_DEBUG("  MsgSize: " << header.msgSize );
    LOG_DEBUG("  MsgFlags: 0x" << std::hex << header.msgFlags << std::dec );
    LOG_DEBUG("  SendingTime: " << header.sendingTime );

    // Дополнительная расшифровка MsgFlags
    LOG_DEBUG("  MsgFlags details:" );
    LOG_DEBUG("    LastFragment: " << ((header.msgFlags & 0x01) ? "Yes" : "No") );
    LOG_DEBUG("    StartOfSnapshot: " << ((header.msgFlags & 0x02) ? "Yes" : "No") );
    LOG_DEBUG("    EndOfSnapshot: " << ((header.msgFlags & 0x04) ? "Yes" : "No") );
    LOG_DEBUG("    IncrementalPacket: " << ((header.msgFlags & 0x08) ? "Yes" : "No") );

    return header;
}

IncrementalPacketHeader SimbaDecoder::decodeIncrementalPacketHeader(const uint8_t* data) {
    IncrementalPacketHeader header;
    header.transactTime = decodeUInt64(data);
    header.exchangeTradingSessionID = decodeUInt32(data + 8);

    // Логирование распарсенных данных
    LOG_DEBUG("Decoded Incremental Packet Header:" );
    LOG_DEBUG("  TransactTime: " << header.transactTime );
    LOG_DEBUG("  ExchangeTradingSessionID: " << header.exchangeTradingSessionID );

    // Дополнительная информация о TransactTime
    time_t seconds = header.transactTime / 1000000000; // Наносекунды в секунды
    struct tm *timeinfo = localtime(&seconds);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    LOG_DEBUG("  TransactTime (human-readable): " << buffer 
              << "." << std::setfill('0') << std::setw(9) 
              << header.transactTime % 1000000000 );

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
    LOG_DEBUG("Decoded SBE Header:" );
    LOG_DEBUG("  BlockLength: " << header.blockLength );
    LOG_DEBUG("  TemplateID: " << header.templateId );
    LOG_DEBUG("  SchemaID: " << header.schemaId );
    LOG_DEBUG("  Version: " << header.version );

    // Дополнительная информация о TemplateID
    LOG_DEBUG("  TemplateID details:" );
    switch (header.templateId) {
        case 15:
            LOG_DEBUG("    Message type: OrderUpdate" );
            break;
        case 16:
            LOG_DEBUG("    Message type: OrderExecution" );
            break;
        case 17:
            LOG_DEBUG("    Message type: OrderBookSnapshot" );
            break;
        default:
	    break;
            LOG_DEBUG("    Message type: Unknown" );
    }

    return header;
}

std::optional<DecodedMessage> SimbaDecoder::decodeMessage(const uint8_t* data, size_t length) {
    if (length < sizeof(MarketDataPacketHeader)) {
        LOG_WARNING("Message too short to contain a valid header" );
        return std::nullopt;
    }

    //LOG_DEBUG << "message: ";
    //for (size_t i = 0; i < length; ++i) {
    //    LOG_DEBUG << std::hex << std::setw(2) << std::setfill('0')
    //              << static_cast<int>(data[i]) << " ";
    //}
    //LOG_DEBUG << std::dec );

    MarketDataPacketHeader mdHeader = decodeMarketDataPacketHeader(data);
    size_t offset = sizeof(MarketDataPacketHeader);

    LOG_DEBUG("sizeof(MarketDataPacketHeader) = " << sizeof(MarketDataPacketHeader) );

    bool isIncrementalPacket = (mdHeader.msgFlags & 0x08) != 0;
    bool isLastFragment = (mdHeader.msgFlags & 0x01) != 0;
    bool isStartOfSnapshot = (mdHeader.msgFlags & 0x02) != 0;
    bool isEndOfSnapshot = (mdHeader.msgFlags & 0x04) != 0;

    LOG_DEBUG("Message Flags Analysis:" );
    LOG_DEBUG("  Raw MsgFlags: 0x" << std::hex << std::setw(4) << std::setfill('0') << mdHeader.msgFlags << std::dec );
    LOG_DEBUG("  IsIncrementalPacket: " << (isIncrementalPacket ? "Yes" : "No") );
    LOG_DEBUG("  IsLastFragment: " << (isLastFragment ? "Yes" : "No") );
    LOG_DEBUG("  IsStartOfSnapshot: " << (isStartOfSnapshot ? "Yes" : "No") );
    LOG_DEBUG("  IsEndOfSnapshot: " << (isEndOfSnapshot ? "Yes" : "No") );

    uint64_t transactTime = 0;
    if (isIncrementalPacket) {
        if (length < offset + sizeof(IncrementalPacketHeader)) {
            LOG_WARNING("Message too short to contain Incremental Packet Header" );
            return std::nullopt;
        }
        IncrementalPacketHeader incHeader = decodeIncrementalPacketHeader(data + offset);
        transactTime = incHeader.transactTime;
        offset += sizeof(IncrementalPacketHeader);

        LOG_DEBUG("offset = " << offset << " sizeof(IncrementalPacketHeader) = " << sizeof(IncrementalPacketHeader) );
    }

    if (length < offset + sizeof(SBEHeader)) {
        LOG_WARNING("Message too short to contain SBE Header" );
        return std::nullopt;
    }

    LOG_DEBUG("Initial SBE Header:" );
    SBEHeader sbeHeader = decodeSBEHeader(data + offset);

    // Раннее отсеивание ненужных типов сообщений
    switch (sbeHeader.templateId) {
        case 15: // OrderUpdate
        case 16: // OrderExecution
        case 17: // OrderBookSnapshot
            break;
        default:
            LOG_DEBUG("Ignoring message with TemplateID: " << sbeHeader.templateId );
            return std::nullopt;
    }

    return processFragment(data + offset, length - offset, mdHeader.msgFlags, transactTime, sbeHeader.templateId);
}

std::optional<DecodedMessage> SimbaDecoder::processFragment(const uint8_t* data, size_t length,
                                                            uint16_t msgFlags, uint64_t transactTime,
                                                            uint16_t templateId) {
    LOG_DEBUG("Entering processFragment" );
    LOG_DEBUG("  Length: " << length );
    LOG_DEBUG("  MsgFlags: 0x" << std::hex << msgFlags << std::dec );
    LOG_DEBUG("  TransactTime: " << transactTime );
    LOG_DEBUG("  TemplateId: " << templateId );

    bool isLastFragment = (msgFlags & 0x01) != 0;
    bool isStartOfSnapshot = (msgFlags & 0x02) != 0;
    bool isEndOfSnapshot = (msgFlags & 0x04) != 0;
    bool isIncrementalPacket = (msgFlags & 0x08) != 0;

    LOG_DEBUG("  IsLastFragment: " << (isLastFragment ? "Yes" : "No") );
    LOG_DEBUG("  IsStartOfSnapshot: " << (isStartOfSnapshot ? "Yes" : "No") );
    LOG_DEBUG("  IsEndOfSnapshot: " << (isEndOfSnapshot ? "Yes" : "No") );
    LOG_DEBUG("  IsIncrementalPacket: " << (isIncrementalPacket ? "Yes" : "No") );

    int32_t securityId = decodeInt32(data);
    LOG_DEBUG("  SecurityId: " << securityId );

    std::pair<int32_t, uint16_t> key(securityId, templateId);

    if (isIncrementalPacket) {
        return processIncrementalPacket(data, length, isLastFragment, templateId, key);
    } else {
        return processSnapshotPacket(data, length, isStartOfSnapshot, isEndOfSnapshot, templateId, securityId);
    }
}

std::optional<DecodedMessage> SimbaDecoder::processIncrementalPacket(const uint8_t* data, size_t length,
                                                                     bool isLastFragment, uint16_t templateId,
                                                                     const std::pair<int32_t, uint16_t>& key) {
    if (!isLastFragment) {
        // Добавляем фрагмент к текущей транзакции
        auto& fragMsg = fragmentedIncrementalMessages[key];
        fragMsg.fragments.push_back(std::vector<uint8_t>(data, data + length));
        LOG_DEBUG("Added incremental fragment. Total fragments: " << fragMsg.fragments.size() );
        return std::nullopt;
    } else {
        // Последний фрагмент или целое сообщение
        std::vector<uint8_t> fullMessage(data, data + length);
        if (fragmentedIncrementalMessages.count(key) > 0) {
            auto& fragMsg = fragmentedIncrementalMessages[key];
            for (const auto& fragment : fragMsg.fragments) {
                fullMessage.insert(fullMessage.begin(), fragment.begin(), fragment.end());
            }
            fragmentedIncrementalMessages.erase(key);
        }
        LOG_DEBUG("Processing complete incremental message. Size: " << fullMessage.size() );
        
        return decodeIncrementalPacket(fullMessage.data(), fullMessage.size());
    }
}

std::optional<DecodedMessage> SimbaDecoder::processSnapshotPacket(const uint8_t* data, size_t length,
                                                                  bool isStartOfSnapshot, bool isEndOfSnapshot,
                                                                  uint16_t templateId,
                                                                  int32_t securityId) {
    assert(templateId == 17 && "Unexpected templateId for OrderBookSnapshot");
    
    LOG_DEBUG(getTimeStamp() << " Processing snapshot packet: "
              << "SecurityID=" << securityId
              << ", Start=" << isStartOfSnapshot
              << ", End=" << isEndOfSnapshot
              << ", Length=" << length );

    if (lastProcessedSecurityId != -1 && lastProcessedSecurityId != securityId) {
        LOG_DEBUG(getTimeStamp() << " INFO: Switched from SecurityID "
                  << lastProcessedSecurityId << " to " << securityId );
        mixedSnapshotsDetected++;
    }
    lastProcessedSecurityId = securityId;

    auto& buffer = fragmentBuffer[securityId];

    if (isStartOfSnapshot) {
        LOG_DEBUG(getTimeStamp() << " Started new snapshot for SecurityID " << securityId );
        buffer.clear();
        buffer.reserve(INITIAL_RESERVE_SIZE);
    }

    buffer.insert(buffer.end(), data, data + length);

    if (isEndOfSnapshot) {
        LOG_DEBUG(getTimeStamp() << " Completing snapshot for SecurityID " << securityId );
        LOG_DEBUG(getTimeStamp() << " Completed snapshot. Total size: " << buffer.size() );

        auto [snapshots, size] = decodeOrderBookSnapshot(buffer.data(), buffer.size());
        if (!snapshots.empty()) {
            totalSnapshotsProcessed++;
            buffer.clear();  // Очищаем буфер после обработки, сохраняя выделенную память
            return DecodedMessage(snapshots[0]);
        }
        buffer.clear();  // Очищаем буфер даже если декодирование не удалось
    } else if (!isStartOfSnapshot) {
        LOG_DEBUG(getTimeStamp() << " Added intermediate fragment for SecurityID " << securityId );
    }

    return std::nullopt;
}

std::optional<DecodedMessage> SimbaDecoder::decodeIncrementalPacket(const uint8_t* data, size_t length) const {
    std::vector<OrderUpdate> updates;
    std::vector<OrderExecution> executions;
    size_t offset = 0;

    while (offset < length) {
        if (offset + sizeof(SBEHeader) > length) {
            LOG_DEBUG("Insufficient data for SBE Header. Remaining: " 
                      << (length - offset) << ", Required: " << sizeof(SBEHeader) );
            break;
        }

        SBEHeader sbeHeader = decodeSBEHeader(data + offset);
        offset += sizeof(SBEHeader);

        if (offset + sbeHeader.blockLength > length) {
            LOG_DEBUG("Insufficient data for message block. Remaining: " 
                      << (length - offset) << ", Required: " << sbeHeader.blockLength );
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
                LOG_DEBUG("Unknown templateId in incremental packet: " << sbeHeader.templateId );
                // Пропускаем неизвестный блок
                offset += sbeHeader.blockLength;
                break;
        }
    }

    if (offset < length) {
        LOG_DEBUG("Warning: " << (length - offset) << " bytes remaining after processing incremental packet" );
    }

    if (!updates.empty()) {
        return DecodedMessage(updates[0]);  // Возвращаем первое обновление
    } else if (!executions.empty()) {
        return DecodedMessage(executions[0]);  // Возвращаем первое исполнение
    }

    return std::nullopt;
}

OrderUpdate SimbaDecoder::decodeOrderUpdate(const uint8_t* data, size_t length) const {
    LOG_DEBUG("Decoding OrderUpdate. Available length: " << length );

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

/*    
    LOG_DEBUG("Decoded OrderUpdate:" )
              << "  MDEntryID: " << update.MDEntryID )
              << "  MDEntryPx: " << update.MDEntryPx.mantissa << "e" << update.MDEntryPx.exponent )
              << "  MDEntrySize: " << update.MDEntrySize )
              << "  MDFlags: 0x" << std::hex << update.MDFlags << std::dec )
              << "  MDFlags2: 0x" << std::hex << update.MDFlags2 << std::dec )
              << "  SecurityID: " << update.SecurityID )
              << "  RptSeq: " << update.RptSeq )
              << "  UpdateAction: " << static_cast<int>(update.UpdateAction) )
              << "  EntryType: " << static_cast<char>(update.EntryType) );
*/
    return update;
}

OrderExecution SimbaDecoder::decodeOrderExecution(const uint8_t* data, size_t length) const {
    LOG_DEBUG("Decoding OrderExecution. Available length: " << length );

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

/*    
    LOG_DEBUG << "Decoded OrderExecution:" )
              << "  MDEntryID: " << execution.MDEntryID )
              << "  MDEntryPx: " << execution.MDEntryPx.mantissa << "e" << execution.MDEntryPx.exponent )
              << "  MDEntrySize: " << execution.MDEntrySize )
              << "  LastPx: " << execution.LastPx.mantissa << "e" << execution.LastPx.exponent )
              << "  LastQty: " << execution.LastQty )
              << "  TradeID: " << execution.TradeID )
              << "  MDFlags: 0x" << std::hex << execution.MDFlags << std::dec )
              << "  MDFlags2: 0x" << std::hex << execution.MDFlags2 << std::dec )
              << "  SecurityID: " << execution.SecurityID )
              << "  RptSeq: " << execution.RptSeq )
              << "  UpdateAction: " << static_cast<int>(execution.UpdateAction) )
              << "  EntryType: " << static_cast<char>(execution.EntryType) );
*/
    return execution;
}

std::pair<std::vector<OrderBookSnapshot>, size_t> SimbaDecoder::decodeOrderBookSnapshot(const uint8_t* data, size_t length) const {
    std::vector<OrderBookSnapshot> snapshots;
    size_t offset = 0;
    constexpr size_t HEADER_SIZE = 19;  // 4 + 4 + 4 + 4 + 2 + 1
    constexpr size_t MIN_ENTRY_SIZE = 8;  // Минимальный размер для OrderBookEntry

    //offset += sizeof(SBEHeader);

    while (offset + HEADER_SIZE <= length) {
        OrderBookSnapshot snapshot;

	offset += sizeof(SBEHeader);

        size_t initialOffset = offset;

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

        LOG_DEBUG("Decoding snapshot for SecurityID: " << snapshot.SecurityID
                  << ", NoMDEntries: " << static_cast<int>(noMDEntries)
                  << ", BlockLength: " << blockLength );

        // Проверка на достаточность данных для всех записей
        if (offset + blockLength * noMDEntries > length) {
            LOG_WARNING("Incomplete snapshot data for SecurityID: " << snapshot.SecurityID );
            break;
        }

	snapshot.entries.reserve(noMDEntries);

	for (int i = 0; i < noMDEntries; ++i) {
    		if (blockLength < MIN_ENTRY_SIZE) {
        		LOG_ERROR("Invalid blockLength for entry " << i );
        		break;
    		}

    		snapshot.entries.emplace_back(decodeOrderBookEntry(data + offset, blockLength));
    		offset += blockLength;
	}

        LOG_DEBUG("Snapshot decoded. Entries: " << snapshot.entries.size()
                  << ", Bytes processed: " << (offset - initialOffset) );

        snapshots.push_back(std::move(snapshot));

        // Проверка на конец данных или неполный следующий снапшот
        if (offset + HEADER_SIZE > length) {
            break;
        }
    }

    LOG_DEBUG("Total snapshots decoded: " << snapshots.size()
              << ", Total bytes processed: " << offset
              << " out of " << length );

    return {snapshots, offset};
}

OrderBookEntry SimbaDecoder::decodeOrderBookEntry(const uint8_t* data, [[maybe_unused]] size_t length) const {
    if (length < sizeof(OrderBookEntry)) {
	    LOG_WARNING("Insufficient data for OrderBookEntry length: " << length << " sizeof(OrderBookEntry) = " << sizeof(OrderBookEntry) );
    }

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

    LOG_DEBUG("  MDEntryID: " << entry.MDEntryID
              << ", MDEntryPx: " << entry.MDEntryPx.mantissa << "e-5"
              << ", MDEntrySize: " << entry.MDEntrySize
              << ", EntryType: " << static_cast<char>(entry.EntryType) );

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

std::string SimbaDecoder::getTimeStamp() {
    auto now = std::chrono::system_clock::now();
    auto nowAsTimeT = std::chrono::system_clock::to_time_t(now);
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&nowAsTimeT), "%Y-%m-%d %H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << nowMs.count();

   return ss.str();
}

void SimbaDecoder::saveDecodedData(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        LOG_ERROR("Unable to open file: " << filename );
        return;
    }

    file << "Decoded data will be saved here.\n";
    // Implement the logic to save decoded data

    file.close();
}

void SimbaDecoder::printStatistics() {
    LOG_INFO("Total snapshots processed: " << totalSnapshotsProcessed);
    LOG_INFO("Mixed snapshots detected: " << mixedSnapshotsDetected);
    if (totalSnapshotsProcessed > 0) {
        double mixedPercentage = (static_cast<double>(mixedSnapshotsDetected) / totalSnapshotsProcessed) * 100.0;
        LOG_INFO("Percentage of mixed snapshots: " << std::fixed << std::setprecision(2) << mixedPercentage << "%");
    }
}
