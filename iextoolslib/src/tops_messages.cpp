#include <chrono>
#include <iextoolslib/pcap_utils.hpp>
#include <iextoolslib/tops_messages.hpp>
#include <iostream>
#include <memory>
#include <regex>
#include <sstream>

using namespace IEXTools;

TopsMessage::TopsMessage(TopsType type) : message_type(type) {}

std::unique_ptr<TopsMessage> TopsMessage::read_message(pcap_cit_t it) {
  auto message_type = read_bytes<Byte>(it);

  switch (message_type) {
    case TradingStatusType:
      return TradingStatusMessage::from_raw_message(it);
    case QuoteUpdateType:
      return QuoteUpdateMessage::from_raw_message(it);
    case TradeReportType:
      return TradeReportMessage::from_raw_message(it);
    default:
      return nullptr;
  }
}

AuctionInformationMessage::AuctionInformationMessage(uint8_t at, int64_t ts, std::array<char, 8> s, uint32_t ps,
                                                     int64_t r, int64_t icp, uint32_t is, uint8_t im, uint8_t en,
                                                     uint32_t sat, int64_t abcp, int64_t crp, int64_t lac, int64_t uac)
    : TopsMessage(AuctionInformationType),
      auction_type(at),
      timestamp(ts),
      symbol(s),
      paired_shared(ps),
      reference_price(r),
      indicative_clearing_price(icp),
      imbalance_shares(is),
      imbalance_side(im),
      extension_number(en),
      scheduled_auction_time(sat),
      auction_book_clearing_price(abcp),
      collar_reference_price(crp),
      lower_auction_collar(lac),
      upper_auction_collar(uac) {}

std::unique_ptr<AuctionInformationMessage> AuctionInformationMessage::from_raw_message(pcap_cit_t it) {
  return std::unique_ptr<AuctionInformationMessage>();
}

TradeBreakMessage::TradeBreakMessage(uint8_t f, int64_t t, std::array<char, 8> s, uint32_t si, int64_t p, int64_t ti)
    : TopsMessage(TradeBreakType), flags(f), timestamp(t), symbol(s), size(si), price(p), trade_id(ti) {}

SecurityDirectoryMessage::SecurityDirectoryMessage(uint8_t f, int64_t t, std::array<char, 8> s, uint32_t rls,
                                                   int64_t app, uint8_t l)
    : TopsMessage(SecurityDirectoryType),
      flags(f),
      timestamp(t),
      symbol(s),
      round_lot_size(rls),
      adjusted_poc_price(app),
      luld_tier(l) {}

TradingStatusMessage::TradingStatusMessage(TradingStatus st, int64_t t, std::array<char, 8> s, std::array<char, 4> r)
    : TopsMessage(TradingStatusType), status(st), timestamp(t), symbol(s), reason(r) {}

OperationalHaltStatusMessage::OperationalHaltStatusMessage(uint8_t st, int64_t t, std::array<char, 8> s)
    : TopsMessage(OperationalHaltStatusType), status(st), timestamp(t), symbol(s) {}
std::unique_ptr<OperationalHaltStatusMessage> OperationalHaltStatusMessage::from_raw_message(pcap_cit_t it) {
  return std::unique_ptr<OperationalHaltStatusMessage>();
}

ShortSalePriceTestStatusMessage::ShortSalePriceTestStatusMessage(uint8_t st, int64_t t, std::array<char, 8> s,
                                                                 uint8_t d)
    : TopsMessage(ShortSalePriceTestStatusType), status(st), timestamp(t), symbol(s), detail(d) {}
std::unique_ptr<ShortSalePriceTestStatusMessage> ShortSalePriceTestStatusMessage::from_raw_message(pcap_cit_t it) {
  return std::unique_ptr<ShortSalePriceTestStatusMessage>();
}

QuoteUpdateMessage::QuoteUpdateMessage(Byte flags, Timestamp timestamp, Symbol symbol, Integer bid_size,
                                       Price bid_price, Integer ask_size, Price ask_price)
    : TopsMessage(QuoteUpdateType),
      flags(flags),
      timestamp(timestamp),
      symbol(symbol),
      bid_size(bid_size),
      bid_price(bid_price),
      ask_size(ask_size),
      ask_price(ask_price) {}

SystemEventMessage::SystemEventMessage(uint8_t se, int64_t ts)
    : TopsMessage(SystemEventType), system_event(se), timestamp(ts) {}
std::unique_ptr<SystemEventMessage> SystemEventMessage::from_raw_message(pcap_cit_t it) {
  return std::unique_ptr<SystemEventMessage>();
}

TradeReportMessage::TradeReportMessage(Byte flags, Timestamp timestamp, Symbol symbol, Integer size, double price,
                                       Long trade_id)
    : TopsMessage(TradeReportType),
      flags(flags),
      timestamp(timestamp),
      symbol(symbol),
      size(size),
      price(price),
      trade_id(trade_id) {}

OfficialPriceMessage::OfficialPriceMessage(uint8_t pt, int64_t t, std::array<char, 8> s, int64_t p)
    : TopsMessage(OfficialPriceType), price_type(pt), timestamp(t), symbol(s), price(p) {}

std::unique_ptr<TradingStatusMessage> TradingStatusMessage::from_raw_message(pcap_cit_t it) {
  auto status = static_cast<TradingStatus>(read_bytes<uint8_t>(it));
  auto timestamp = read_bytes<Timestamp>(it);
  auto symbol = read_bytes<Symbol>(it);
  auto reason = read_bytes<std::array<char, 4>>(it);

  return std::make_unique<TradingStatusMessage>(status, timestamp, symbol, reason);
};

std::string TradingStatusMessage::to_string() const {
  std::stringstream ss;
  ss << "TradingStatusMessage | timestamp=" << timestamp << " symbol=" << symbol << " status=" << status;

  if (status == HaltedAllUSMarkets || status == HaltReleaseOrderAcceptance) {
    ss << " reason=" << std::string(reason.cbegin(), reason.cend());
  }

  return ss.str();
}

std::unique_ptr<QuoteUpdateMessage> QuoteUpdateMessage::from_raw_message(pcap_cit_t it) {
  auto flags = read_bytes<Byte>(it);
  auto timestamp = read_bytes<Timestamp>(it);
  auto symbol = read_bytes<Symbol>(it);
  auto bid_size = read_bytes<Integer>(it);
  auto bid_price = read_bytes<Price>(it);
  auto ask_price = read_bytes<Price>(it);
  auto ask_size = read_bytes<Integer>(it);

  return std::make_unique<QuoteUpdateMessage>(flags, timestamp, symbol, bid_size, bid_price, ask_size, ask_price);
}

std::string QuoteUpdateMessage::to_string() const {
  std::stringstream ss;
  ss << "QuoteUpdateMessage | timestamp=" << timestamp << " symbol=" << symbol << " bid/ask=$" << bid_price << " ("
     << bid_size << ") /$" << ask_price << " (" << ask_size << ")";

  return ss.str();
}

std::unique_ptr<TradeReportMessage> TradeReportMessage::from_raw_message(pcap_cit_t it) {
  auto flags = read_bytes<Byte>(it);
  auto timestamp = read_bytes<Timestamp>(it);
  auto symbol = read_bytes<Symbol>(it);
  auto size = read_bytes<Integer>(it);
  auto price = price_to_double(read_bytes<Price>(it));
  auto trade_id = read_bytes<Long>(it);

  return std::make_unique<TradeReportMessage>(flags, timestamp, symbol, size, price, trade_id);
}

std::string TradeReportMessage::to_string() const {
  std::stringstream ss;
  ss << "TradeReportMessage | timestamp=" << timestamp << " symbol=" << symbol << " price=$" << price
     << " size=" << size;

  return ss.str();
}

std::ostream& operator<<(std::ostream& os, const IEXTools::TradingStatus& obj) {
  switch (obj) {
    case IEXTools::HaltedAllUSMarkets:
      return os << "H (0x48): Trading halted accross all US equity markets";
    case HaltReleaseOrderAcceptance:
      return os
             << "O (0x4f): Trading halt released into an Order Acceptance Period on IEX (IEX-listed securities only)";
    case PauseAndOrderAcceptance:
      return os << "P (0x50): Trading paused and Order Acceptance Period on IEX (IEX-listed securities only)";
    case Trading:
      return os << "T (0x54): Trading on IEX";
    default:
      return os;
  }
}

std::ostream& operator<<(std::ostream& os, const IEXTools::Symbol& obj) {
  os << std::regex_replace(std::string(obj.cbegin(), obj.cend()), std::regex("\\s+$"), std::string(""));
  return os;
}