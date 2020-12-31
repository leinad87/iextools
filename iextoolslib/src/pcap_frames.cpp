#include <iextoolslib/pcap_frames.hpp>
#include <iextoolslib/pcap_utils.hpp>
#include <iostream>
#include <utility>

using namespace IEXTools;

EthernetFrame::EthernetFrame(std::array<std::byte, 6> dst, std::array<std::byte, 6> src, uint16_t type)
    : dst(dst), src(src), type(type) {}

EthernetFrame EthernetFrame::read_from_block(pcap_cit_t& it) {
  auto dst = read_bytes<std::array<std::byte, 6>>(it);
  auto src = read_bytes<std::array<std::byte, 6>>(it);
  auto type = read_bytes<uint16_t>(it);

  return EthernetFrame(dst, src, type);
}

IPv4Frame::IPv4Frame(uint8_t version, uint8_t ihl, uint8_t dscp, uint8_t ecn, uint16_t total_length,
                     uint16_t identification, uint16_t flags, uint8_t ttl, uint8_t protocol, uint16_t header_checksum,
                     uint32_t src_addr, uint32_t dst_addr)
    : version(version),
      ihl(ihl),
      dscp(dscp),
      ecn(ecn),
      total_length(total_length),
      identification(identification),
      flags(flags),
      ttl(ttl),
      protocol(protocol),
      header_checksum(header_checksum),
      src_addr(src_addr),
      dst_addr(dst_addr) {}

IPv4Frame IPv4Frame::read_from_block(pcap_cit_t& it) {
  auto byte0 = read_bytes<uint8_t>(it);

  auto version = (byte0 & 0xf0) >> 4;
  auto ihl = byte0 & 0x0f;

  auto byte1 = read_bytes<uint8_t>(it);
  auto dscp = (byte1 & 0x7c) >> 2;
  auto ecn = byte1 & 0x03;
  auto total_length = read_bytes<uint16_t>(it);
  swap_endian<uint16_t>(total_length);
  auto identification = read_bytes<uint16_t>(it);
  swap_endian<uint16_t>(identification);
  auto flags = read_bytes<uint16_t>(it);
  swap_endian<uint16_t>(flags);
  auto ttl = read_bytes<uint8_t>(it);
  auto protocol = read_bytes<uint8_t>(it);
  auto header_checksum = read_bytes<uint16_t>(it);
  swap_endian<uint16_t>(header_checksum);
  auto src_addr = read_bytes<uint32_t>(it);
  auto dst_addr = read_bytes<uint32_t>(it);

  if (ihl > 5) {
    std::cerr << "IHL=" << ihl << ", IPv4 Options not implemented, from this point onwards behaviour is not guaranteed"
              << std::endl;
    std::exit(1);
  }

  return IPv4Frame(version, ihl, dscp, ecn, total_length, identification, flags, ttl, protocol, header_checksum,
                   src_addr, dst_addr);
}

UDPFrame::UDPFrame(uint16_t source_port, uint16_t destination_port, uint16_t length, uint16_t checksum)
    : source_port(source_port), destination_port(destination_port), length(length), checksum(checksum) {}

UDPFrame UDPFrame::read_from_block(pcap_cit_t& it) {
  auto source_port = read_bytes<uint16_t>(it);
  swap_endian<uint16_t>(source_port);
  auto destination_port = read_bytes<uint16_t>(it);
  swap_endian<uint16_t>(destination_port);
  auto length = read_bytes<uint16_t>(it);
  swap_endian<uint16_t>(length);
  auto checksum = read_bytes<uint16_t>(it);
  swap_endian<uint16_t>(checksum);

  return UDPFrame(source_port, destination_port, length, checksum);
}

IexTpFrame::IexTpFrame(Byte version, Short message_protocol_id, Integer channel_id, Integer session_id,
                       Short payload_length, Short message_count, Long stream_offset,
                       Long first_message_sequence_number, Timestamp send_time, pcap_cit_t data_it)
    : version(version),
      message_protocol_id(message_protocol_id),
      channel_id(channel_id),
      session_id(session_id),
      payload_length(payload_length),
      message_count(message_count),
      stream_offset(stream_offset),
      first_message_sequence_number(first_message_sequence_number),
      send_time(send_time),
      data_it(data_it) {}

IexTpFrame IexTpFrame::read_from_block(pcap_cit_t& it) {
  auto version = read_bytes<Byte>(it);
  read_bytes<Byte>(it);  // reserved
  auto message_protocol_id = read_bytes<Short>(it);
  auto channel_id = read_bytes<Integer>(it);
  auto session_id = read_bytes<Integer>(it);
  auto payload_length = read_bytes<Short>(it);
  auto message_count = read_bytes<Short>(it);
  auto stream_offset = read_bytes<Long>(it);
  auto first_message_sequence_number = read_bytes<Long>(it);
  auto send_time = read_bytes<Long>(it);

  return IexTpFrame(version, message_protocol_id, channel_id, session_id, payload_length, message_count, stream_offset,
                    first_message_sequence_number, send_time, it);
}

PcapBlock::PcapBlock(pcap_cit_t it_begin, pcap_cit_t it_end) : begin(it_begin), end(it_end) {}

EnhancedPacketBlock::EnhancedPacketBlock(pcap_cit_t begin, pcap_cit_t end, uint32_t interface_id, double timestamp,
                                         uint32_t captured_packet_length, uint32_t original_packet_length,
                                         EthernetFrame ethernet, IPv4Frame ip, UDPFrame udp, IexTpFrame iex_tps)
    : PcapBlock(begin, end),
      interface_id(interface_id),
      timestamp(timestamp),
      captured_packet_length(captured_packet_length),
      original_packet_length(original_packet_length),
      ethernet(std::move(ethernet)),
      ip(ip),
      udp(udp),
      iex_tp(std::move(iex_tps)) {}

PcapFrame::PcapFrame(int type, unsigned frame_number, size_t frame_length, pcap_cit_t iterator,
                     std::unique_ptr<PcapBlock> block)
    : type(type),
      type_name(get_frame_type_name(type)),
      frame_number(frame_number),
      frame_length(frame_length),
      iterator(iterator),
      block(std::move(block)) {}

std::string PcapFrame::get_frame_type_name(int type) {
  switch (type) {
    case 0x0A0D0D0A:
      return "Header Block";
    case 0x00000001:
      return "Interface Description Block";
    case 0x00000002:
      return "Packet Block";
    case 0x00000003:
      return "Simple Packet Block";
    case 0x00000004:
      return "Name Resolution Block";
    case 0x00000005:
      return "Interface Statistics Block";
    case 0x00000006:
      return "Enhanced Packet Block";
    case 0x00000BAD:
      return "Custom Block (copiable)";
    case 0x40000BAD:
      return "Custom Block (non-copiable)";
    default:
      return "Unknown Block";
  }
}

std::ostream& operator<<(std::ostream& os, const IEXTools::EthernetFrame& obj) {
  os << "Ethernet II, src=" << IEXTools::mac_addr_formatter(obj.src) << " dst=" << IEXTools::mac_addr_formatter(obj.dst)
     << " type=" << std::hex << obj.type << std::dec;

  return os;
}

std::ostream& operator<<(std::ostream& os, const IEXTools::IPv4Frame& obj) {
  os << "IPv" << std::to_string(obj.version) << " IHL=" << std::to_string(obj.ihl)
     << " total_length=" << obj.total_length << " Identification=0x" << std::hex << obj.identification << std::dec
     << " (" << obj.identification << ") Flags=0x" << std::hex << obj.flags << std::dec
     << " TTL=" << static_cast<int>(obj.ttl) << " Protocol=" << static_cast<int>(obj.protocol) << std::hex
     << " checksum=0x" << obj.header_checksum << std::dec << " Source=" << ip_addr_formatter(obj.src_addr)
     << " Destination=" << ip_addr_formatter(obj.dst_addr);

  return os;
}

std::ostream& operator<<(std::ostream& os, const IEXTools::UDPFrame& obj) {
  os << "UDP src_port=" << obj.source_port << " dst_port=" << obj.destination_port << " length=" << obj.length
     << " checksum=0x" << std::hex << obj.checksum << std::dec;
  return os;
}

std::ostream& operator<<(std::ostream& os, const IEXTools::IexTpFrame& obj) {
  os << "IEX-TP v" << static_cast<int>(obj.version) << " Protocol=0x" << std::hex << obj.message_protocol_id << std::dec
     << " Send Time=" << obj.send_time << " Length=" << obj.payload_length << " Messages=" << obj.message_count
     << " Channel=" << obj.channel_id << " Session=" << obj.session_id;
  return os;
}
