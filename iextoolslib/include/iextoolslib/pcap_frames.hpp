#ifndef __IEXTOOLSLIB_PCAP_TYPES_HPP__
#define __IEXTOOLSLIB_PCAP_TYPES_HPP__

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "types.hpp"

namespace IEXTools {

static const int IP_FRAME_TRANSPORT_PROTOCOL_UDP = 17;

struct EthernetFrame {
  EthernetFrame(std::array<std::byte, 6> dst, std::array<std::byte, 6> src, uint16_t type);

  static EthernetFrame read_from_block(pcap_cit_t& it);

  const std::array<std::byte, 6> dst;
  const std::array<std::byte, 6> src;
  const uint16_t type;
};

struct IPv4Frame {
  IPv4Frame(uint8_t version, uint8_t ihl, uint8_t dscp, uint8_t ecn, uint16_t total_length, uint16_t identification,
            uint16_t flags, uint8_t ttl, uint8_t protocol, uint16_t header_checksum, uint32_t src_addr,
            uint32_t dst_addr);

  const uint8_t version;
  const uint8_t ihl;
  const uint8_t dscp;
  const uint8_t ecn;
  const uint16_t total_length;
  const uint16_t identification;
  const uint16_t flags;
  const uint8_t ttl;
  const uint8_t protocol;
  const uint16_t header_checksum;
  const uint32_t src_addr;
  const uint32_t dst_addr;

  static IPv4Frame read_from_block(pcap_cit_t& it);
};

struct UDPFrame {
  UDPFrame(uint16_t source_port, uint16_t destination_port, uint16_t length, uint16_t checksum);
  const uint16_t source_port;
  const uint16_t destination_port;
  const uint16_t length;
  const uint16_t checksum;

  static UDPFrame read_from_block(pcap_cit_t& it);
};

struct IexTpFrame {
  IexTpFrame(Byte version, Short message_protocol_id, Integer channel_id, Integer session_id, Short payload_length,
             Short message_count, Long stream_offset, Long first_message_sequence_number, Timestamp send_time,
             pcap_cit_t data_it);

  const Byte version;
  const Short message_protocol_id;
  const Integer channel_id;
  const Integer session_id;
  const Short payload_length;
  const Short message_count;
  const Long stream_offset;
  const Long first_message_sequence_number;
  const Timestamp send_time;
  const pcap_cit_t data_it;

  static IexTpFrame read_from_block(pcap_cit_t& it);
};

struct PcapBlock {
  PcapBlock(pcap_cit_t begin, pcap_cit_t end);

  virtual ~PcapBlock() = default;

  pcap_cit_t begin;
  pcap_cit_t end;
};

struct EnhancedPacketBlock : public PcapBlock {
  EnhancedPacketBlock(pcap_cit_t begin, pcap_cit_t end, uint32_t interface_id, double timestamp,
                      uint32_t captured_packet_length, uint32_t original_packet_length, EthernetFrame ethernet,
                      IPv4Frame ip, UDPFrame udp, IexTpFrame iex_tp);

  const uint32_t interface_id;
  const double timestamp;
  const uint32_t captured_packet_length;
  const uint32_t original_packet_length;
  const EthernetFrame ethernet;
  const IPv4Frame ip;
  const UDPFrame udp;
  const IexTpFrame iex_tp;
};

struct PcapFrame {
  static const int HEADER_BLOCK_TYPE = 0x0A0D0D0A;
  static const int INTERFACE_DESCRIPTION_BLOCK_TYPE = 0x00000001;
  static const int PACKET_BLOCK_TYPE = 0x00000002;
  static const int SIMPLE_PACKET_BLOCK_TYPE = 0x00000003;
  static const int NAME_RESOLUTION_BLOCK_TYPE = 0x00000004;
  static const int INTERFACE_STATISTICS_BLOCK_TYPE = 0x00000005;
  static const int ENHANCED_PACKET_BLOCK_TYPE = 0x00000006;
  static const int CUSTOM_BLOCK_COPIABLE_TYPE = 0x00000BAD;
  static const int CUSTOM_BLOCK_NON_COPIABLE_TYPE = 0x40000BAD;

  PcapFrame(int type, unsigned frame_number, size_t frame_length, pcap_cit_t iterator,
            std::unique_ptr<PcapBlock> block);

  const int type;
  const std::string type_name;
  const unsigned frame_number;
  const size_t frame_length;
  const pcap_cit_t iterator;
  std::unique_ptr<PcapBlock> block;

 private:
  static std::string get_frame_type_name(int frame_type);
};

}  // namespace IEXTools

std::ostream& operator<<(std::ostream& os, const IEXTools::EthernetFrame& obj);
std::ostream& operator<<(std::ostream& os, const IEXTools::IPv4Frame& obj);
std::ostream& operator<<(std::ostream& os, const IEXTools::UDPFrame& obj);
std::ostream& operator<<(std::ostream& os, const IEXTools::IexTpFrame& obj);

#endif
