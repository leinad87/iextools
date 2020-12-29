#include <chrono>
#include <fstream>
#include <iextoolslib/pcap.hpp>
#include <iextoolslib/pcap_frames.hpp>
#include <iextoolslib/pcap_utils.hpp>
#include <iextoolslib/tops_messages.hpp>
#include <iomanip>
#include <iostream>
#include <memory>

using namespace IEXTools;

PcapReader::PcapReader(const std::string& file_path)
    : file_path(file_path), file_size(get_file_size(file_path)), data(load_data()), frames(get_frames()) {}

std::size_t PcapReader::get_file_size(const std::string& path) {
  std::ifstream is(path);
  is.seekg(0, std::ios_base::end);
  std::size_t size = is.tellg();
  is.close();

  return size;
}

std::vector<std::byte> IEXTools::PcapReader::load_data() {
  std::vector<std::byte> d(file_size / sizeof(std::byte));
  std::ifstream is(file_path);
  is.read((char*)(&d.at(0)), file_size);
  is.close();

  return d;
}

std::vector<PcapFrame> PcapReader::get_frames() {
  auto it = data.cbegin();
  std::vector<PcapFrame> _frames;

  for (unsigned n = 0; it != data.cend(); ++n) {
    pcap_cit_t begin_block_it{it};

    auto block_type = read_bytes<uint32_t>(it);
    auto block_length_begin_frame = read_bytes<uint32_t>(it);
    auto it_begin{it};                                      // points to the first byte containing pcap data block
    it += block_length_begin_frame - sizeof(uint32_t) * 3;  // skip to the end of the block
    auto it_end{it};  // points to the next byte after the end of the pcap data block
    auto block_length_end_frame = read_bytes<uint32_t>(it);

    if (block_length_begin_frame != block_length_end_frame) {
      std::cerr << "length mismatch" << std::endl;
      std::exit(1);
    }

    _frames.emplace_back(block_type, n, block_length_begin_frame, begin_block_it,
                         std::unique_ptr<PcapBlock>(get_block(block_type, it_begin, it_end)));
  }

  return _frames;
}

std::unique_ptr<PcapBlock> PcapReader::get_block(int block_type, pcap_cit_t it_begin, pcap_cit_t it_end) {
  switch (block_type) {
    case PcapFrame::ENHANCED_PACKET_BLOCK_TYPE:
      return get_enhanced_packet_block(it_begin, it_end);
    // TODO: implement the rest of swith cases
    case PcapFrame::HEADER_BLOCK_TYPE:
    case PcapFrame::INTERFACE_DESCRIPTION_BLOCK_TYPE:
    case PcapFrame::PACKET_BLOCK_TYPE:
    case PcapFrame::SIMPLE_PACKET_BLOCK_TYPE:
    case PcapFrame::NAME_RESOLUTION_BLOCK_TYPE:
    case PcapFrame::INTERFACE_STATISTICS_BLOCK_TYPE:
    case PcapFrame::CUSTOM_BLOCK_COPIABLE_TYPE:
    case PcapFrame::CUSTOM_BLOCK_NON_COPIABLE_TYPE:
    default:
      return nullptr;
  }
}

std::unique_ptr<EnhancedPacketBlock> PcapReader::get_enhanced_packet_block(pcap_cit_t it_begin, pcap_cit_t it_end) {
  auto interface_id = read_bytes<uint32_t>(it_begin);
  uint64_t timestamp_high = read_bytes<uint32_t>(it_begin);
  timestamp_high = timestamp_high << 32;
  uint64_t timestamp_low = read_bytes<uint32_t>(it_begin);
  // TODO: use ts_resol from INTERFACE_DESCRIPTION_BLOCK_TYPE for calculating timestamp, here using defaults
  double timestamp = static_cast<double>(timestamp_high | timestamp_low) / 1e6;
  auto captured_packet_length = read_bytes<uint32_t>(it_begin);
  auto original_packet_length = read_bytes<uint32_t>(it_begin);
  auto ethernet = EthernetFrame::read_from_block(it_begin);
  auto ip = IPv4Frame::read_from_block(it_begin);

  if (ip.protocol != IP_FRAME_TRANSPORT_PROTOCOL_UDP) {
    // TODO: manage TCP connections?
    std::cerr << "Transport protocol is (" << ip.protocol << "). Only UPD (17) is supported.";
    std::exit(1);
  }

  auto transport = UDPFrame::read_from_block(it_begin);
  auto iex = IexTpFrame::read_from_block(it_begin);

  if (it_begin >= it_end) {
    // TODO: manage situation
    std::cerr << "Read out of boundaries" << std::endl;
    std::exit(1);
  }

  return std::make_unique<EnhancedPacketBlock>(it_begin, it_end, interface_id, timestamp, captured_packet_length,
                                               original_packet_length, ethernet, ip, transport, iex);
}

std::ostream& operator<<(std::ostream& os, const IEXTools::PcapFrame& obj) {
  os << "Pcap Frame No: " << std::setw(8) << std::setfill('0') << obj.frame_number << " Type: " << obj.type_name
     << " (0x" << std::hex << obj.type << std::dec << ") Len: " << obj.frame_length;

  return os;
}

std::ostream& operator<<(std::ostream& os, const IEXTools::EnhancedPacketBlock& obj) {
  os << "EnhancedPacketBlock - " << std::setprecision(17) << "timestamp=" << obj.timestamp
     << " captured_len=" << obj.captured_packet_length;

  return os;
}