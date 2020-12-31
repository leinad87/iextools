#ifndef IEX_TOOLS_TYPES_HPP
#define IEX_TOOLS_TYPES_HPP

#include <array>
#include <memory>
#include <vector>

namespace IEXTools {

using pcap_cit_t = std::vector<std::byte>::const_iterator;
using Byte = uint8_t;
using Long = int64_t;
using Integer = uint32_t;
using Price = int64_t;
using Short = uint16_t;
using Timestamp = int64_t;
using Symbol = std::array<char, 8>;

enum TopsType {
  AuctionInformationType = 0x41,
  TradeBreakType = 0x42,
  SecurityDirectoryType = 0x44,
  TradingStatusType = 0x48,
  OperationalHaltStatusType = 0x4f,
  ShortSalePriceTestStatusType = 0x50,
  QuoteUpdateType = 0x51,
  SystemEventType = 0x53,
  TradeReportType = 0x54,
  OfficialPriceType = 0x58
};

enum TradingStatus {
  HaltedAllUSMarkets = 0x48,
  HaltReleaseOrderAcceptance = 0x4f,
  PauseAndOrderAcceptance = 0x50,
  Trading = 0x54
};

}  // namespace IEXTools

#endif  // IEX_TOOLS_TYPES_HPP
