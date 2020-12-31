#include <fstream>
#include <iextoolslib/pcap_utils.hpp>
#include <iextoolslib/tops.hpp>
#include <iostream>
#include <sstream>

using namespace IEXTools;

TopsReader::TopsReader(const std::string& file_path, const std::string& out_dir) : pcap(file_path), out_dir(out_dir) {
  parse_data();
  dump_files();
}

std::vector<std::unique_ptr<TopsMessage>> TopsReader::get_messages(EnhancedPacketBlock* packet) {
  std::vector<std::unique_ptr<TopsMessage>> messages{};
  auto& iex = packet->iex_tp;

  unsigned total_length = 0;

  if (iex.payload_length > 0 && iex.message_count > 0) {
    messages.reserve(iex.message_count);

    for (int i = 0; i < iex.message_count; ++i) {
      auto it{packet->iex_tp.data_it + total_length};
      auto message_length = read_bytes<Short>(it);
      total_length += message_length + sizeof(message_length);

      if (total_length > iex.payload_length) {
        std::exit(1);
      }

      auto message_type = read_bytes<Byte>(it);

      if (message_type == TradeReportType) {
        auto message = TradeReportMessage::from_raw_message(it);
        std::stringstream ss;
        ss << message->timestamp << "," << message->size << "," << message->price;
        auto symbol{symbol_to_string(message->symbol)};
        if (auto iter = data.find(symbol); iter != data.end()) {
          iter->second.emplace_back(ss.str());
        } else {
          data[symbol] = {ss.str()};
        }

      } else {
        it += message_length - sizeof(message_type);
      }
    }
  }

  if (total_length != iex.payload_length) {
    std::cerr << "total_length != iex.payload_length" << std::endl;
    // std:exit(1);
  }

  return messages;
}

void TopsReader::parse_data() {
  for (auto& pcap_frame : pcap) {
    if (pcap_frame.type == PcapFrame::ENHANCED_PACKET_BLOCK_TYPE) {
      auto* enhanced_packet = dynamic_cast<EnhancedPacketBlock*>(pcap_frame.block.get());

      if (enhanced_packet != nullptr) {
        get_messages(enhanced_packet);
      } else {
        std::cerr << "Error accessing Enhanced Packet Block: bad dynamic casting" << std::endl;
      }
    }
  }
}
void TopsReader::dump_files() const {
  for (auto const& [symbol, values] : data) {
    std::filesystem::path out_file_path{out_dir};
    out_file_path /= std::string(symbol.cbegin(), symbol.cend()) + ".csv";
    std::ofstream os(out_file_path);

    std::cout << out_file_path << std::endl;

    for (auto& value : values) {
      os << value << "\n";
    }
    os.close();
  }
}
