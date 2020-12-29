#ifndef __IEXTOOLSLIB_TOPS_HPP__
#define __IEXTOOLSLIB_TOPS_HPP__

#include <array>
#include <memory>
#include <regex>
#include <string>
#include <vector>

#include "pcap.hpp"
#include "types.hpp"

namespace IEXTools {

struct TopsMessage {
  explicit TopsMessage(IEXTools::TopsType type);

  const TopsType message_type;

  static std::unique_ptr<TopsMessage> read_message(pcap_cit_t it);

  [[nodiscard]] virtual std::string to_string() const { return ""; }
};

struct AuctionInformationMessage : public TopsMessage {
  AuctionInformationMessage(uint8_t at, int64_t ts, std::array<char, 8> s, uint32_t ps, int64_t r, int64_t icp,
                            uint32_t is, uint8_t im, uint8_t en, uint32_t sat, int64_t abcp, int64_t crp, int64_t lac,
                            int64_t uac);

  const uint8_t auction_type;
  const int64_t timestamp;
  const std::array<char, 8> symbol;
  const uint32_t paired_shared;
  const int64_t reference_price;
  const int64_t indicative_clearing_price;
  const uint32_t imbalance_shares;
  const uint8_t imbalance_side;
  const uint8_t extension_number;
  const uint32_t scheduled_auction_time;
  const int64_t auction_book_clearing_price;
  const int64_t collar_reference_price;
  const int64_t lower_auction_collar;
  const int64_t upper_auction_collar;

  static std::unique_ptr<AuctionInformationMessage> from_raw_message(pcap_cit_t it);
};

struct TradeBreakMessage : public TopsMessage {
  TradeBreakMessage(uint8_t f, int64_t t, std::array<char, 8> s, uint32_t si, int64_t p, int64_t ti);

  const uint8_t flags;
  const int64_t timestamp;
  const std::array<char, 8> symbol;
  const uint32_t size;
  const int64_t price;
  const int64_t trade_id;
};

struct SecurityDirectoryMessage : public TopsMessage {
  SecurityDirectoryMessage(uint8_t f, int64_t t, std::array<char, 8> s, uint32_t rls, int64_t app, uint8_t l);

  const uint8_t flags;
  const int64_t timestamp;
  const std::array<char, 8> symbol;
  const uint32_t round_lot_size;
  const int64_t adjusted_poc_price;
  const uint8_t luld_tier;
};

struct TradingStatusMessage : public TopsMessage {
  TradingStatusMessage(TradingStatus st, Timestamp t, Symbol s, std::array<char, 4> r);

  const TradingStatus status;
  const Timestamp timestamp;
  const Symbol symbol;
  const std::array<char, 4> reason;

  static std::unique_ptr<TradingStatusMessage> from_raw_message(pcap_cit_t it);

  [[nodiscard]] std::string to_string() const override;
};

struct OperationalHaltStatusMessage : public TopsMessage {
  OperationalHaltStatusMessage(uint8_t st, int64_t t, std::array<char, 8> s);

  const uint8_t status;
  const int64_t timestamp;
  const std::array<char, 8> symbol;

  static std::unique_ptr<OperationalHaltStatusMessage> from_raw_message(pcap_cit_t it);
};

struct ShortSalePriceTestStatusMessage : public TopsMessage {
  ShortSalePriceTestStatusMessage(uint8_t st, int64_t t, std::array<char, 8> s, uint8_t d);

  const uint8_t status;
  const int64_t timestamp;
  const std::array<char, 8> symbol;
  const uint8_t detail;

  static std::unique_ptr<ShortSalePriceTestStatusMessage> from_raw_message(pcap_cit_t it);
};

struct QuoteUpdateMessage : public TopsMessage {
  QuoteUpdateMessage(Byte flags, Timestamp timestamp, Symbol symbol, Integer bid_size, Price bid_price,
                     Integer ask_size, Price ask_price);

  const Byte flags;
  const Timestamp timestamp;
  const Symbol symbol;
  const Integer bid_size;
  const Price bid_price;
  const Integer ask_size;
  const Price ask_price;

  static std::unique_ptr<QuoteUpdateMessage> from_raw_message(pcap_cit_t it);

  [[nodiscard]] std::string to_string() const override;
};

struct SystemEventMessage : public TopsMessage {
  SystemEventMessage(uint8_t se, int64_t ts);

  const uint8_t system_event;
  const int64_t timestamp;

  static std::unique_ptr<SystemEventMessage> from_raw_message(pcap_cit_t it);
};

struct TradeReportMessage : public TopsMessage {
  TradeReportMessage(Byte flags, Timestamp timestamp, Symbol symbol, Integer size, double price, Long trade_id);

  const Byte flags;
  const Timestamp timestamp;
  const Symbol symbol;
  const Integer size;
  const double price;
  const Long trade_id;

  static std::unique_ptr<TradeReportMessage> from_raw_message(pcap_cit_t it);

  [[nodiscard]] std::string to_string() const override;
};

struct OfficialPriceMessage : public TopsMessage {
  OfficialPriceMessage(uint8_t pt, int64_t t, std::array<char, 8> s, int64_t p);

  const uint8_t price_type;
  const int64_t timestamp;
  const std::array<char, 8> symbol;
  const int64_t price;
};

}  // namespace IEXTools

std::ostream& operator<<(std::ostream& os, const IEXTools::TradingStatus& obj);
std::ostream& operator<<(std::ostream& os, const IEXTools::Symbol& obj);

#endif