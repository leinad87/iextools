//
// Created by Juan on 24/12/2020.
//

#ifndef IEX_TOOLS_TOPS_HPP
#define IEX_TOOLS_TOPS_HPP

#include <vector>
#include <map>
#include <memory>
#include "pcap.hpp"
#include "tops_messages.hpp"

namespace IEXTools {
struct TopsReader {
  explicit TopsReader(const std::string& file_path);

  void parse_data();

 private:

  std::vector<std::unique_ptr<TopsMessage>> get_messages(EnhancedPacketBlock* packet);

  PcapReader pcap;
  std::map<std::string, std::vector<std::string>> data;

  void dump_files() const;
};

}  // namespace IEXTools

#endif  // IEX_TOOLS_TOPS_HPP
